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

// --- 强制日志宏，匹配你的搜索字符串 "Perfare_Packet" ---
#undef LOG_TAG
#define LOG_TAG "Perfare_Packet"
#undef LOGI
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// --- 32位环境下的 HexDump：跳过 C# 数组头 (0x10) ---
std::string HexDump32(void* ptr, int len) {
    if (!ptr) return "NULL_PTR";
    // 32 位 IL2CPP：byte[] 数组的对象头通常是 16 字节 (0x10)
    // 如果打印出来发现数据不对，可以尝试改成 +0x8 或 +0xC 观察
    unsigned char* raw_data = (unsigned char*)ptr + 0x10; 
    
    std::stringstream ss;
    // 限制打印长度，防止 Logcat 溢出
    int safe_len = (len > 128) ? 128 : len;
    for (int i = 0; i < safe_len; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)raw_data[i] << " ";
    }
    return ss.str();
}

// --- 拦截函数：针对 32 位参数位置 ---
// instance=R0, buffer=R1, length=R2
void my_PacketEncode_32(void* instance, void* buffer, int length) {
    LOGI(">>>> [32位封包触发] 长度: %d", length);
    if (buffer != nullptr && length > 0) {
        LOGI(">>>> [数据内容]: %s", HexDump32(buffer, length).c_str());
    }
    // 暴力 Hook 无法返回，打印完后让它随风而去（游戏会崩，但日志已留存）
    LOGI(">>>> [记录完毕，正在退出流程]");
}

// --- 32位 ARM 指令替换 (LDR PC 跳地址) ---
void raw_patch_32(void* target, void* replace) {
    unsigned long page_size = sysconf(_SC_PAGESIZE);
    unsigned long addr = (unsigned long)target & ~(page_size - 1);
    mprotect((void*)addr, page_size * 2, PROT_READ | PROT_WRITE | PROT_EXEC);

    uint32_t* code = (uint32_t*)target;
    // 指令：LDR PC, [PC, #-4] -> 0xe51ff004
    // 紧接着存放目标地址
    code[0] = 0xe51ff004; 
    code[1] = (uint32_t)replace;
    
    __builtin___clear_cache((char*)target, (char*)target + 8);
}

void hack_start(const char *game_data_dir) {
    LOGI("Zygisk 32位业务线程启动...");
    sleep(15); // 等待游戏解密

    void *handle = xdl_open("libil2cpp.so", 0);
    if (handle) {
        LOGI("libil2cpp.so Base: %p", handle);
        
        // 1. 跑 Dump 流程
        il2cpp_api_init(handle);
        il2cpp_dump(game_data_dir);

        // 2. 使用 32 位 RVA 偏移 (请务必确认这是 32 位 dump 出来的地址)
        // 示例偏移：0x123456
        size_t packet_encode_rva = 0xad18e4; 
        void* target_addr = (void*)((size_t)handle + packet_encode_rva);
        
        LOGI("定位目标: %p，开始 32 位硬核劫持...", target_addr);
        raw_patch_32(target_addr, (void*)my_PacketEncode_32);
        LOGI("注入成功！现在请在游戏中操作发包。");

        xdl_close(handle);
    }
}

// --- 官方原版 JNI 函数，确保注入入口不丢 ---

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
