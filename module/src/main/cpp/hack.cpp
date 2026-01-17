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

// --- 重新定义日志宏，确保搜索 "Perfare_Packet" 必出结果 ---
#undef LOG_TAG
#define LOG_TAG "Perfare_Packet"
#undef LOGI
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// --- ARM64 HexDump：跳过 0x20 字节的对象头 ---
std::string HexDump64(void* ptr, int len) {
    if (!ptr || len <= 0) return "NULL";
    // 64位 IL2CPP: C# byte[] 数据从指针偏移 32 字节 (0x20) 开始
    unsigned char* raw_data = (unsigned char*)ptr + 0x20; 
    std::stringstream ss;
    for (int i = 0; i < (len > 128 ? 128 : len); ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)raw_data[i] << " ";
    }
    return ss.str();
}

// --- 拦截函数 ---
void* my_PacketEncode(void* instance, void* buffer, int length) {
    if (buffer != nullptr && length > 0) {
        LOGI(">>>> [ARM64 封包抓获] 长度: %d", length);
        LOGI(">>>> [数据内容]: %s", HexDump64(buffer, length).c_str());
    }
    // 这种 Hook 方式会破坏原函数，打印完后游戏会崩，但日志会保存在 logcat 中
    return nullptr; 
}

// --- ARM64 暴力指令替换 Hook ---
void patch_hook_64(void* target, void* replace) {
    unsigned long page_size = sysconf(_SC_PAGESIZE);
    uintptr_t addr = (uintptr_t)target & ~(page_size - 1);
    mprotect((void*)addr, page_size * 2, PROT_READ | PROT_WRITE | PROT_EXEC);

    uint32_t* code = (uint32_t*)target;
    // ARM64 跳转指令: LDR X16, #8; BR X16; [ADDR_64]
    code[0] = 0x58000050; 
    code[1] = 0xd61f0200;
    *((void**)(code + 2)) = replace;
    
    __builtin___clear_cache((char*)target, (char*)target + 16);
}

void hack_start(const char *game_data_dir) {
    LOGI("Zygisk 64位业务线程启动...");
    sleep(15); 

    void *handle = xdl_open("libil2cpp.so", 0);
    if (handle) {
        LOGI("libil2cpp.so 已找到: %p", handle);
        
        // 1. 执行原版 Dump
        il2cpp_api_init(handle);
        il2cpp_dump(game_data_dir);

        // 2. 定位并 Hook (请确保此 RVA 偏移来自 64 位的 dump.cs)
        // 假设偏移是 0x123456
        size_t packet_rva = 0x11b54c8; 
        void* target_addr = (void*)((uintptr_t)handle + packet_rva);
        
        LOGI("目标函数地址: %p，开始注入...", target_addr);
        patch_hook_64(target_addr, (void*)my_PacketEncode);
        LOGI("Hook 完成，请在游戏中尝试发包！");

        xdl_close(handle);
    }
}

// --- 以下所有原版函数保持不动，确保注入环境稳定 ---

std::string GetLibDir(JavaVM *vms) {
    JNIEnv *env = nullptr;
    vms->AttachCurrentThread(&env, nullptr);
    jclass activity_thread_clz = env->FindClass("android/app/ActivityThread");
    if (activity_thread_clz != nullptr) {
        jmethodID currentApplicationId = env->GetStaticMethodID(activity_thread_clz, "currentApplication", "()Landroid/app/Application;");
        jobject application = env->CallStaticObjectMethod(activity_thread_clz, currentApplicationId);
        if (application) {
            jclass application_clazz = env->GetObjectClass(application);
            jmethodID get_app_info = env->GetMethodID(application_clazz, "getApplicationInfo", "()Landroid/content/pm/ApplicationInfo;");
            jobject app_info = env->CallObjectMethod(application, get_app_info);
            jfieldID libDirId = env->GetFieldID(env->GetObjectClass(app_info), "nativeLibraryDir", "Ljava/lang/String;");
            auto jstr = (jstring) env->GetObjectField(app_info, libDirId);
            auto path = env->GetStringUTFChars(jstr, nullptr);
            std::string res(path);
            env->ReleaseStringUTFChars(jstr, path);
            return res;
        }
    }
    return {};
}

static std::string GetNativeBridgeLibrary() {
    auto value = std::array<char, PROP_VALUE_MAX>();
    __system_property_get("ro.dalvik.vm.native.bridge", value.data());
    return {value.data()};
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
