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

// --- 自动适配架构的 HexDump ---
std::string HexDump(void* ptr, int len) {
    if (!ptr || len <= 0) return "null";
    
#if defined(__aarch64__)
    // 64位系统：byte[] 对象头是 0x20
    unsigned char* raw_data = (unsigned char*)ptr + 0x20; 
#else
    // 32位系统：byte[] 对象头是 0x10
    unsigned char* raw_data = (unsigned char*)ptr + 0x10; 
#endif

    std::stringstream ss;
    int safe_len = (len > 128) ? 128 : len;
    for (int i = 0; i < safe_len; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)raw_data[i] << " ";
    }
    return ss.str();
}

// --- 拦截函数 ---
void* my_PacketEncode(void* instance, void* buffer, int length) {
    if (buffer != nullptr && length > 0) {
        LOGI(">>>> [抓获封包] 长度: %d", length);
        LOGI(">>>> [内容]: %s", HexDump(buffer, length).c_str());
    }
    // 这种暴力 Hook 无法回跳，打印完后游戏会崩，但我们要的就是那一秒的日志
    return nullptr; 
}

// --- 适配 32/64 位的暴力指令替换 ---
void patch_hook(void* target, void* replace) {
    unsigned long page_size = sysconf(_SC_PAGESIZE);
    unsigned long addr = (unsigned long)target & ~(page_size - 1);
    mprotect((void*)addr, page_size * 2, PROT_READ | PROT_WRITE | PROT_EXEC);

#if defined(__aarch64__)
    // --- 64位跳转指令 (16字节) ---
    uint32_t* code = (uint32_t*)target;
    code[0] = 0x58000050; // LDR X16, #8
    code[1] = 0xd61f0200; // BR X16
    *((void**)(code + 2)) = replace;
    __builtin___clear_cache((char*)target, (char*)target + 16);
#else
    // --- 32位跳转指令 (8字节) ---
    uint32_t* code = (uint32_t*)target;
    code[0] = 0xe51ff004; // LDR PC, [PC, #-4]
    code[1] = (uint32_t)replace; // 这里的强转在 32 位下是安全的
    __builtin___clear_cache((char*)target, (char*)target + 8);
#endif
}

void hack_start(const char *game_data_dir) {
    LOGI("Zygisk 业务线程启动，检测架构中...");
    
    // 给游戏一点启动时间
    sleep(15);

    void *handle = xdl_open("libil2cpp.so", 0);
    if (handle) {
        LOGI("libil2cpp.so 已加载: %p", handle);
        
        // 1. 跑原版 Dump
        il2cpp_api_init(handle);
        il2cpp_dump(game_data_dir);

        // 2. 定位 PacketEncode (请确保 RVA 偏移正确)
        // 注意：如果是 32 位游戏，偏移量必须是 32 位 dump.cs 里的地址！
        size_t packet_rva = 0x123456; 
        void* target_addr = (void*)((size_t)handle + packet_rva);
        
        LOGI("注入目标地址: %p", target_addr);
        patch_hook(target_addr, (void*)my_PacketEncode);
        LOGI("Hook 注入成功！");

        xdl_close(handle);
    }
}

// --- 以下原样保留官方入口函数 ---

std::string GetLibDir(JavaVM *vms) {
    JNIEnv *env = nullptr;
    vms->AttachCurrentThread(&env, nullptr);
    jclass activity_thread_clz = env->FindClass("android/app/ActivityThread");
    if (activity_thread_clz != nullptr) {
        jmethodID currentApplicationId = env->GetStaticMethodID(activity_thread_clz, "currentApplication", "()Landroid/app/Application;");
        jobject application = env->CallStaticObjectMethod(activity_thread_clz, currentApplicationId);
        if (application) {
            jclass application_clazz = env->GetObjectClass(application);
            jmethodID get_application_info = env->GetMethodID(application_clazz, "getApplicationInfo", "()Landroid/content/pm/ApplicationInfo;");
            jobject application_info = env->CallObjectMethod(application, get_application_info);
            jfieldID native_library_dir_id = env->GetFieldID(env->GetObjectClass(application_info), "nativeLibraryDir", "Ljava/lang/String;");
            auto jstr = (jstring) env->GetObjectField(application_info, native_library_dir_id);
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

#if defined(__arm__) || defined(__aarch64__)
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    auto game_data_dir = (const char *) reserved;
    std::thread t(hack_start, game_data_dir);
    t.detach();
    return JNI_VERSION_1_6;
}
#endif
