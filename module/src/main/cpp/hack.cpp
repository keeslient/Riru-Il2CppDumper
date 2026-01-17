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

// --- 强制日志宏，确保 PowerShell 执行 adb logcat -s Perfare_Packet:V 必出内容 ---
#undef LOG_TAG
#define LOG_TAG "Perfare_Packet"
#undef LOGI
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// --- 十六进制打印工具 ---
std::string HexDump(void* ptr, int len) {
    if (!ptr || len <= 0) return "NULL";
    // 64位 IL2CPP: byte[] 对象的数据起始偏移是 0x20
    unsigned char* raw_data = (unsigned char*)ptr + 0x20; 
    std::stringstream ss;
    int safe_len = (len > 64) ? 64 : len; 
    for (int i = 0; i < safe_len; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)raw_data[i] << " ";
    }
    return ss.str();
}

// --- 拦截函数 ---
void* my_PacketEncode(void* instance, void* buffer, int length) {
    if (buffer != nullptr && length > 0) {
        LOGI(">>>> [ARM64 封包抓获] 长度: %d", length);
        LOGI(">>>> [原始数据]: %s", HexDump(buffer, length).c_str());
    }
    // 暴力覆盖指令无法返回，打印完后游戏会崩。
    // 但在崩之前，封包数据已经打到 Logcat 了！
    return nullptr; 
}

// --- ARM64 暴力指令替换 ---
void patch_hook_raw(void* target, void* replace) {
    unsigned long page_size = sysconf(_SC_PAGESIZE);
    uintptr_t addr = (uintptr_t)target & ~(page_size - 1);
    mprotect((void*)addr, page_size * 2, PROT_READ | PROT_WRITE | PROT_EXEC);

    uint32_t* code = (uint32_t*)target;
    // ARM64 绝对跳转指令 (16字节)
    code[0] = 0x58000050; // LDR X16, #8
    code[1] = 0xd61f0200; // BR X16
    *((void**)(code + 2)) = replace;
    
    __builtin___clear_cache((char*)target, (char*)target + 16);
}

void hack_start(const char *game_data_dir) {
    LOGI("Zygisk 业务线程启动，静候 15 秒环境稳定...");
    sleep(15); 

    void *handle = xdl_open("libil2cpp.so", 0);
    if (handle) {
        LOGI("libil2cpp.so 已找到，地址: %p", handle);
        
        // 1. 跑官方原版 Dump
        il2cpp_api_init(handle);
        il2cpp_dump(game_data_dir);
        LOGI("官方 Dump 流程执行完毕。");

        // 2. 定位并 Hook (！！请修改这里的 0x123456 为你真正的 RVA 偏移地址！！)
        size_t packet_rva = 0x11b54c8; 
        void* target_addr = (void*)((uintptr_t)handle + packet_rva);
        
        LOGI("目标函数地址计算成功: %p，注入 Hook...", target_addr);
        patch_hook_raw(target_addr, (void*)my_PacketEncode);
        LOGI("Hook 注入完成！去游戏中发包吧！");

        xdl_close(handle);
    } else {
        LOGE("未搜寻到 libil2cpp.so");
    }
}

// --- 下面全是官方原版必须的函数，补全后就不会再报 undefined symbol 了 ---

std::string GetLibDir(JavaVM *vms) {
    JNIEnv *env = nullptr;
    vms->AttachCurrentThread(&env, nullptr);
    jclass activity_thread_clz = env->FindClass("android/app/ActivityThread");
    if (activity_thread_clz) {
        jmethodID currentAppId = env->GetStaticMethodID(activity_thread_clz, "currentApplication", "()Landroid/app/Application;");
        jobject application = env->CallStaticObjectMethod(activity_thread_clz, currentAppId);
        if (application) {
            jclass application_clazz = env->GetObjectClass(application);
            jmethodID getAppInfo = env->GetMethodID(application_clazz, "getApplicationInfo", "()Landroid/content/pm/ApplicationInfo;");
            jobject app_info = env->CallObjectMethod(application, getAppInfo);
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

/**
 * 核心修复点：main.cpp 调用的是这个 hack_prepare 函数
 */
void hack_prepare(const char *game_data_dir, void *data, size_t length) {
    LOGI("hack_prepare 触发，正在转入逻辑执行...");
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
