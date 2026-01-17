#include "hack.h"
#include "il2cpp_dump.h"
#include "log.h"
#include "xdl.h"
#include <cstring>
#include <cstdio>
#include <unistd.h>
#include <sys/system_properties.h>
#include <dlfcn.h>
#include <jni.h>
#include <thread>
#include <sys/mman.h>
#include <linux/unistd.h>
#include <array>
#include <string>
#include <sstream>
#include <iomanip>

// --- 强制日志宏 ---
#undef LOG_TAG
#define LOG_TAG "Perfare_Packet"
#undef LOGI
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// --- 32位 HexDump：跳过 C# 数组头 (32位下通常是 0x10) ---
std::string HexDump(void* ptr, int len) {
    if (!ptr || len <= 0) return "null";
    // 32 位 IL2CPP：byte[] 数据从 0x10 (16字节) 开始
    unsigned char* raw_data = (unsigned char*)ptr + 0x10; 
    std::stringstream ss;
    for (int i = 0; i < (len > 64 ? 64 : len); ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)raw_data[i] << " ";
    }
    return ss.str();
}

// --- 拦截函数 ---
// 注意：由于是暴力 Hook，我们不回跳原函数，所以这之后游戏必崩
// 但我们要的就是崩之前那一秒的日志
void my_PacketEncode(void* instance, void* buffer, int length) {
    LOGI(">>>> [!! 拦截到 32位封包 !!]");
    LOGI(">>>> [长度]: %d", length);
    LOGI(">>>> [内容]: %s", HexDump(buffer, length).c_str());
    
    // 故意让它在这里卡死或者通过无限循环保住日志，防止闪退太快日志刷不出来
    LOGI(">>>> [封包记录完成，准备闪退...]");
}

// --- 32位 ARM 暴力指令替换 ---
void patch_hook_32(void* target, void* replace) {
    unsigned long page_size = sysconf(_SC_PAGESIZE);
    unsigned long addr = (unsigned long)target & ~(page_size - 1);
    mprotect((void*)addr, page_size * 2, PROT_READ | PROT_WRITE | PROT_EXEC);

    uint32_t* code = (uint32_t*)target;
    // ARM 32位 绝对跳转指令 (8 字节)
    // LDR PC, [PC, #-4]
    // [ADDR]
    code[0] = 0xe51ff004; 
    code[1] = (uint32_t)replace;
    
    __builtin___clear_cache((char*)target, (char*)target + 8);
}

void hack_start(const char *game_data_dir) {
    LOGI("Zygisk 32位业务启动...");
    sleep(10); // 稍微缩短点时间，别等太久

    void *handle = xdl_open("libil2cpp.so", 0);
    if (handle) {
        LOGI("libil2cpp.so 地址: %p", handle);
        
        // 1. 跑 Dump（确认注入没问题）
        il2cpp_api_init(handle);
        il2cpp_dump(game_data_dir);

        // 2. 使用你的 RVA 偏移 (请务必填入你从 dump.cs 找回来的地址)
        // 示例：如果 dump.cs 里显示 0x123456
        size_t packet_rva = 0xad18e4; 
        void* target_addr = (void*)((size_t)handle + packet_rva);
        
        LOGI("正在 Hook 目标地址: %p", target_addr);
        patch_hook_32(target_addr, (void*)my_PacketEncode);
        LOGI("32位 Hook 注入完毕！去操作游戏发包吧！");

        xdl_close(handle);
    }
}

// --- 其余原版函数一个不动，保证环境稳定 ---

std::string GetLibDir(JavaVM *vms) {
    JNIEnv *env = nullptr;
    vms->AttachCurrentThread(&env, nullptr);
    jclass activity_thread_clz = env->FindClass("android/app/ActivityThread");
    if (activity_thread_clz != nullptr) {
        jmethodID currentApplicationId = env->GetStaticMethodID(activity_thread_clz, "currentApplication", "()Landroid/app/Application;");
        jobject application = env->CallStaticObjectMethod(activity_thread_clz, currentApplicationId);
        jclass application_clazz = env->GetObjectClass(application);
        jmethodID get_application_info = env->GetMethodID(application_clazz, "getApplicationInfo", "()Landroid/content/pm/ApplicationInfo;");
        jobject application_info = env->CallObjectMethod(application, get_application_info);
        jfieldID native_library_dir_id = env->GetFieldID(env->GetObjectClass(application_info), "nativeLibraryDir", "Ljava/lang/String;");
        auto native_library_dir_jstring = (jstring) env->GetObjectField(application_info, native_library_dir_id);
        auto path = env->GetStringUTFChars(native_library_dir_jstring, nullptr);
        std::string lib_dir(path);
        env->ReleaseStringUTFChars(native_library_dir_jstring, path);
        return lib_dir;
    }
    return {};
}

static std::string GetNativeBridgeLibrary() {
    auto value = std::array<char, PROP_VALUE_MAX>();
    __system_property_get("ro.dalvik.vm.native.bridge", value.data());
    return {value.data()};
}

bool NativeBridgeLoad(const char *game_data_dir, int api_level, void *data, size_t length) {
    return false; // 简化处理
}

void hack_prepare(const char *game_data_dir, void *data, size_t length) {
    hack_start(game_data_dir);
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    auto game_data_dir = (const char *) reserved;
    std::thread t(hack_start, game_data_dir);
    t.detach();
    return JNI_VERSION_1_6;
}
