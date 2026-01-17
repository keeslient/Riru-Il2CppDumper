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

// --- 自动适配 32/64 位的 HexDump ---
std::string HexDump(void* ptr, int len) {
    if (!ptr || len <= 0) return "null";

#if defined(__LP64__)
    // 64位系统 (arm64/x86_64)：byte[] 对象头是 0x20
    unsigned char* raw_data = (unsigned char*)ptr + 0x20; 
#else
    // 32位系统 (arm/x86)：byte[] 对象头是 0x10
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
    // 暴力 Hook 无法回跳，执行完必崩，但 Log 已经留下了
    return nullptr; 
}

// --- 适配全架构的暴力指令替换 ---
void patch_hook(void* target, void* replace) {
    unsigned long page_size = sysconf(_SC_PAGESIZE);
    uintptr_t addr = (uintptr_t)target & ~(page_size - 1);
    mprotect((void*)addr, page_size * 2, PROT_READ | PROT_WRITE | PROT_EXEC);

#if defined(__LP64__)
    // --- 64位通用跳转 (适用于 arm64 和 x86_64 编译通过) ---
    uint32_t* code = (uint32_t*)target;
    #if defined(__aarch64__)
        code[0] = 0x58000050; // LDR X16, #8
        code[1] = 0xd61f0200; // BR X16
        *((void**)(code + 2)) = replace;
    #else
        // x86_64 环境只为了让编译通过，不写具体指令
        LOGI("非 ARM64 架构，仅跳过指令写入");
    #endif
    __builtin___clear_cache((char*)target, (char*)target + 16);
#else
    // --- 32位通用跳转 ---
    uint32_t* code = (uint32_t*)target;
    #if defined(__arm__)
        code[0] = 0xe51ff004; // LDR PC, [PC, #-4]
        code[1] = (uint32_t)(uintptr_t)replace; // 两次强转解决编译警告
    #endif
    __builtin___clear_cache((char*)target, (char*)target + 8);
#endif
}

void hack_start(const char *game_data_dir) {
    LOGI("Zygisk 业务线程启动，正在等待 libil2cpp.so...");
    
    // 延迟 15 秒等待环境解密
    sleep(15);

    void *handle = xdl_open("libil2cpp.so", 0);
    if (handle) {
        LOGI("libil2cpp.so 已找到: %p", handle);
        
        il2cpp_api_init(handle);
        il2cpp_dump(game_data_dir);
        LOGI("原版 Dump 流程结束。");

        // --- 核心定位逻辑 ---
        // 这里的 0x123456 必须改成你从 dump.cs 里看到的 RVA 地址！
        size_t packet_rva = 0x123456; 
        void* target_addr = (void*)((uintptr_t)handle + packet_rva);
        
        LOGI("目标函数地址: %p，开始注入...", target_addr);
        patch_hook(target_addr, (void*)my_PacketEncode);
        LOGI("注入完成！请在游戏中触发封包发送。");

        xdl_close(handle);
    } else {
        LOGE("未找到 libil2cpp.so");
    }
}

// --- 保持原版 JNI 入口 ---
std::string GetLibDir(JavaVM *vms) {
    JNIEnv *env = nullptr;
    vms->AttachCurrentThread(&env, nullptr);
    jclass activity_thread_clz = env->FindClass("android/app/ActivityThread");
    if (activity_thread_clz) {
        jmethodID currentApp = env->GetStaticMethodID(activity_thread_clz, "currentApplication", "()Landroid/app/Application;");
        jobject application = env->CallStaticObjectMethod(activity_thread_clz, currentApp);
        jclass app_clazz = env->GetObjectClass(application);
        jmethodID getAppInfo = env->GetMethodID(app_clazz, "getApplicationInfo", "()Landroid/content/pm/ApplicationInfo;");
        jobject app_info = env->CallObjectMethod(application, getAppInfo);
        jfieldID libDirId = env->GetFieldID(env->GetObjectClass(app_info), "nativeLibraryDir", "Ljava/lang/String;");
        auto jstr = (jstring) env->GetObjectField(app_info, libDirId);
        auto path = env->GetStringUTFChars(jstr, nullptr);
        std::string res(path);
        env->ReleaseStringUTFChars(jstr, path);
        return res;
    }
    return {};
}

#if defined(__arm__) || defined(__aarch64__)
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    auto game_data_dir = (const char *) reserved;
    std::thread t(hack_start, game_data_dir);
    t.detach();
    return JNI_VERSION_1_6;
}
#endif
