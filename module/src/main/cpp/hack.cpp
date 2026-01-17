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

#undef LOG_TAG
#define LOG_TAG "Perfare_Packet"
#undef LOGI
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// 打印内存数据的工具
std::string HexDump(void* ptr, int len) {
    if (!ptr) return "NULL";
    unsigned char* raw_data = (unsigned char*)ptr; 
    std::stringstream ss;
    for (int i = 0; i < len; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)raw_data[i] << " ";
    }
    return ss.str();
}

// 拦截函数
void* my_PacketEncode(void* instance, void* buffer, int length) {
    // 如果进到这里，说明 Hook 真正生效了！
    LOGI(">>>> [Bingo!] 成功拦截到封包调用！长度: %d", length);
    if (buffer != nullptr) {
        // 尝试读取数据 (尝试 0x20 偏移)
        unsigned char* data_ptr = (unsigned char*)buffer + 0x20;
        LOGI(">>>> [内容预览]: %s", HexDump(data_ptr, 32).c_str());
    }
    return nullptr; 
}

// 暴力 Hook 逻辑
void patch_hook_64(void* target, void* replace) {
    unsigned long page_size = sysconf(_SC_PAGESIZE);
    uintptr_t addr = (uintptr_t)target & ~(page_size - 1);
    mprotect((void*)addr, page_size * 2, PROT_READ | PROT_WRITE | PROT_EXEC);

    uint32_t* code = (uint32_t*)target;
    code[0] = 0x58000050; // LDR X16, #8
    code[1] = 0xd61f0200; // BR X16
    *((void**)(code + 2)) = replace;
    
    __builtin___clear_cache((char*)target, (char*)target + 16);
}

void hack_start(const char *game_data_dir) {
    LOGI("Zygisk 业务线程启动...");
    sleep(15); 

    void *handle = xdl_open("libil2cpp.so", 0);
    if (handle) {
        LOGI("libil2cpp.so 地址: %p", handle);
        il2cpp_api_init(handle);
        il2cpp_dump(game_data_dir);

        // --- 核心调试逻辑 ---
        // 1. 请确认这个偏移量是你从 dump.cs 的 PacketEncode 找到的 RVA
        size_t packet_rva = 0x123456; 
        void* target_addr = (void*)((uintptr_t)handle + packet_rva);
        
        // 【关键校验】打印注入前后的指令，看看到底写进去没有
        LOGI("注入前指令 (Original): %s", HexDump(target_addr, 16).c_str());
        
        patch_hook_64(target_addr, (void*)my_PacketEncode);
        
        LOGI("注入后指令 (Modified): %s", HexDump(target_addr, 16).c_str());
        LOGI("如果上面两行不一样，说明内存已修改。如果游戏没崩，说明偏移量 0x%lx 找错了！", packet_rva);

        xdl_close(handle);
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
void hack_prepare(const char *game_data_dir, void *data, size_t length) {
    hack_start(game_data_dir);
}
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    auto game_data_dir = (const char *) reserved;
    std::thread t(hack_start, game_data_dir);
    t.detach();
    return JNI_VERSION_1_6;
}
