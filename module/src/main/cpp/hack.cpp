//
// Created by Perfare on 2020/7/4.
//

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

// --- 强制修正日志定义 ---
#undef LOG_TAG
#define LOG_TAG "Perfare_Packet"
#undef LOGI
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// --- 内存数据转 Hex 字符串工具 ---
std::string HexDump(void* ptr, int len) {
    if (!ptr) return "NULL";
    unsigned char* raw_data = (unsigned char*)ptr; 
    std::stringstream ss;
    for (int i = 0; i < len; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)raw_data[i] << " ";
    }
    return ss.str();
}

// --- 封包拦截函数 ---
void* my_PacketEncode(void* instance, void* buffer, int length) {
    LOGI(">>>> [Bingo] PacketEncode 命中！长度: %d", length);
    if (buffer != nullptr) {
        // 尝试打印 buffer 指向的数据（如果是 C# byte[]，数据在 +0x20 处）
        unsigned char* data_ptr = (unsigned char*)buffer + 0x20;
        LOGI(">>>> [内容预览]: %s", HexDump(data_ptr, length > 32 ? 32 : length).c_str());
    }
    // 暴力 Hook 无法回跳，执行完这里进程会崩，我们要的就是这一瞬间的日志
    return nullptr; 
}

// --- ARM64 指令劫持核心逻辑 ---
void patch_hook_64(void* target, void* replace) {
    unsigned long page_size = sysconf(_SC_PAGESIZE);
    uintptr_t addr = (uintptr_t)target & ~(page_size - 1);
    mprotect((void*)addr, page_size * 2, PROT_READ | PROT_WRITE | PROT_EXEC);

    uint32_t* code = (uint32_t*)target;
    // ARM64 强制跳转
    code[0] = 0x58000050; // LDR X16, #8
    code[1] = 0xd61f0200; // BR X16
    *((void**)(code + 2)) = replace;
    
    __builtin___clear_cache((char*)target, (char*)target + 16);
}

void hack_start(const char *game_data_dir) {
    LOGI("Zygisk 注入逻辑启动...");
    sleep(15); // 给游戏一点解密时间

    void *handle = xdl_open("libil2cpp.so", 0);
    if (handle) {
        LOGI("libil2cpp.so 句柄获取成功: %p", handle);
        
        // 1. 先执行官方原版的 Dump
        il2cpp_api_init(handle);
        il2cpp_dump(game_data_dir);
        LOGI("官方 Dump 流程执行完毕。");

        // 2. 定位 PacketEncode (请务必确认这个 RVA 地址来自 64 位的 dump.cs)
        size_t packet_rva = 0x11b54c8; 
        void* target_addr = (void*)((uintptr_t)handle + packet_rva);
        
        // 【关键修复】：这里使用 %zx 打印 size_t，防止编译报错
        LOGI("注入前指令 (Original): %s", HexDump(target_addr, 16).c_str());
        
        patch_hook_64(target_addr, (void*)my_PacketEncode);
        
        LOGI("注入后指令 (Modified): %s", HexDump(target_addr, 16).c_str());
        LOGI("如果上面两行不一样，说明内存已修改。偏移量 0x%zx", packet_rva);

        xdl_close(handle);
    }
}

// --- 以下原封不动保留你要求的原版辅助函数 ---

std::string GetLibDir(JavaVM *vms) {
    JNIEnv *env = nullptr;
    vms->AttachCurrentThread(&env, nullptr);
    jclass activity_thread_clz = env->FindClass("android/app/ActivityThread");
    if (activity_thread_clz != nullptr) {
        jmethodID currentApplicationId = env->GetStaticMethodID(activity_thread_clz, "currentApplication", "()Landroid/app/Application;");
        if (currentApplicationId) {
            jobject application = env->CallStaticObjectMethod(activity_thread_clz, currentApplicationId);
            jclass application_clazz = env->GetObjectClass(application);
            if (application_clazz) {
                jmethodID get_application_info = env->GetMethodID(application_clazz, "getApplicationInfo", "()Landroid/content/pm/ApplicationInfo;");
                if (get_application_info) {
                    jobject application_info = env->CallObjectMethod(application, get_application_info);
                    jfieldID native_library_dir_id = env->GetFieldID(env->GetObjectClass(application_info), "nativeLibraryDir", "Ljava/lang/String;");
                    if (native_library_dir_id) {
                        auto native_library_dir_jstring = (jstring) env->GetObjectField(application_info, native_library_dir_id);
                        auto path = env->GetStringUTFChars(native_library_dir_jstring, nullptr);
                        std::string lib_dir(path);
                        env->ReleaseStringUTFChars(native_library_dir_jstring, path);
                        return lib_dir;
                    }
                }
            }
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
