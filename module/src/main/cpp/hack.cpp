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

// --- 强制定义日志宏，确保 adb logcat -s Perfare_Packet:V 必出内容 ---
#undef LOG_TAG
#define LOG_TAG "Perfare_Packet"
#undef LOGI
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// --- 专门打印封包的工具 ---
std::string HexDump(void* ptr, int len) {
    if (!ptr || len <= 0) return "NULL_PTR";
    // 关键：IL2CPP 的 byte[] 数组数据在偏移 0x20 (32字节) 处开始
    unsigned char* raw_data = (unsigned char*)ptr + 0x20; 
    std::stringstream ss;
    for (int i = 0; i < (len > 128 ? 128 : len); ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)raw_data[i] << " ";
    }
    return ss.str();
}

// --- 拦截函数：在封包加密前抓取它 ---
void* my_PacketEncode(void* instance, void* buffer, int length) {
    if (buffer != nullptr && length > 0) {
        LOGI(">>>> [抓获封包] 长度:%d", length);
        LOGI(">>>> [封包内容]: %s", HexDump(buffer, length).c_str());
    }
    // 提示：指令覆盖 Hook 无法简单跳回原函数。
    // 执行完打印后，这里返回 nullptr 通常会导致游戏发包失败并闪退。
    // 但在闪退前，你的封包数据已经通过上面的 LOGI 成功打印出来了。
    return nullptr; 
}

// --- 暴力指令替换函数 (ARM64 专用，不依赖任何 Hook 库) ---
void patch_hook(void* target, void* replace) {
    unsigned long page_size = sysconf(_SC_PAGESIZE);
    unsigned long addr = (unsigned long)target & ~(page_size - 1);
    // 修改内存页权限为可写
    mprotect((void*)addr, page_size * 2, PROT_READ | PROT_WRITE | PROT_EXEC);

    uint32_t* code = (uint32_t*)target;
    // ARM64 强制跳转指令 (16 字节)
    code[0] = 0x58000050; // LDR X16, #8
    code[1] = 0xd61f0200; // BR X16
    *((void**)(code + 2)) = replace; // 跳转目标地址
    
    // 刷新 CPU 缓存，使修改立即生效
    __builtin___clear_cache((char*)target, (char*)target + 16);
}

void hack_start(const char *game_data_dir) {
    LOGI("Zygisk 业务线程已启动，等待 15 秒环境稳定...");
    bool load = false;
    
    // 延迟 15 秒，等游戏完成解密和自检
    sleep(15);

    for (int i = 0; i < 15; i++) {
        void *handle = xdl_open("libil2cpp.so", 0);
        if (handle) {
            load = true;
            // handle 就是 libil2cpp.so 在内存中的起始（Base）地址
            LOGI("libil2cpp.so 已加载，Base 地址: %p", handle);
            
            // 1. 执行原有的 Dump 逻辑 (恢复官方原本功能)
            il2cpp_api_init(handle);
            il2cpp_dump(game_data_dir);
            LOGI("Dump 流程执行完毕。");

            // 2. 【核心】通过偏移定位 PacketEncode
            // 请把 0x123456 改成你从 dump.cs 里搜到的 RVA 地址
            size_t packet_encode_offset = 0xad18e4; 
            void* target_addr = (void*)((size_t)handle + packet_encode_offset);
            
            LOGI("目标函数地址计算成功: %p，开始注入 Hook...", target_addr);
            patch_hook(target_addr, (void*)my_PacketEncode);
            LOGI("Hook 注入成功！现在请在游戏中操作发包。");

            xdl_close(handle);
            break;
        } else {
            sleep(2);
        }
    }
}

// --- 以下原封不动保留官方原版函数，确保注入流程不出错 ---

std::string GetLibDir(JavaVM *vms) {
    JNIEnv *env = nullptr;
    vms->AttachCurrentThread(&env, nullptr);
    jclass activity_thread_clz = env->FindClass("android/app/ActivityThread");
    if (activity_thread_clz != nullptr) {
        jmethodID currentApplicationId = env->GetStaticMethodID(activity_thread_clz, "currentApplication", "()Landroid/app/Application;");
        if (currentApplicationId) {
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
    }
    return {};
}

static std::string GetNativeBridgeLibrary() {
    auto value = std::array<char, PROP_VALUE_MAX>();
    __system_property_get("ro.dalvik.vm.native.bridge", value.data());
    return {value.data()};
}

struct NativeBridgeCallbacks {
    uint32_t version;
    void *initialize;
    void *(*loadLibrary)(const char *libpath, int flag);
    void *(*getTrampoline)(void *handle, const char *name, const char *shorty, uint32_t len);
    void *isSupported;
    void *getAppEnv;
    void *isCompatibleWith;
    void *getSignalHandler;
    void *unloadLibrary;
    void *getError;
    void *isPathSupported;
    void *initAnonymousNamespace;
    void *createNamespace;
    void *linkNamespaces;
    void *(*loadLibraryExt)(const char *libpath, int flag, void *ns);
};

bool NativeBridgeLoad(const char *game_data_dir, int api_level, void *data, size_t length) {
    sleep(5);
    auto libart = dlopen("libart.so", RTLD_NOW);
    auto JNI_GetCreatedJavaVMs = (jint (*)(JavaVM **, jsize, jsize *)) dlsym(libart, "JNI_GetCreatedJavaVMs");
    JavaVM *vms_buf[1];
    jsize num_vms;
    jint status = JNI_GetCreatedJavaVMs(vms_buf, 1, &num_vms);
    if (status == JNI_OK && num_vms > 0) {
        JavaVM *vms = vms_buf[0];
        auto lib_dir = GetLibDir(vms);
        if (lib_dir.empty()) return false;
        auto nb = dlopen("libhoudini.so", RTLD_NOW);
        if (!nb) nb = dlopen(GetNativeBridgeLibrary().data(), RTLD_NOW);
        if (nb) {
            auto callbacks = (NativeBridgeCallbacks *) dlsym(nb, "NativeBridgeItf");
            if (callbacks) {
                int fd = syscall(__NR_memfd_create, "anon", MFD_CLOEXEC);
                ftruncate(fd, (off_t) length);
                void *mem = mmap(nullptr, length, PROT_WRITE, MAP_SHARED, fd, 0);
                memcpy(mem, data, length);
                munmap(mem, length);
                char path[PATH_MAX];
                snprintf(path, PATH_MAX, "/proc/self/fd/%d", fd);
                void *arm_handle = (api_level >= 26) ? callbacks->loadLibraryExt(path, RTLD_NOW, (void *) 3) : callbacks->loadLibrary(path, RTLD_NOW);
                if (arm_handle) {
                    auto init = (void (*)(JavaVM *, void *)) callbacks->getTrampoline(arm_handle, "JNI_OnLoad", nullptr, 0);
                    init(vms, (void *) game_data_dir);
                    return true;
                }
            }
        }
    }
    return false;
}

void hack_prepare(const char *game_data_dir, void *data, size_t length) {
    int api_level = android_get_device_api_level();
#if defined(__i386__) || defined(__x86_64__)
    if (!NativeBridgeLoad(game_data_dir, api_level, data, length)) {
#endif
        hack_start(game_data_dir);
#if defined(__i386__) || defined(__x86_64__)
    }
#endif
}

#if defined(__arm__) || defined(__aarch64__)
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    auto game_data_dir = (const char *) reserved;
    std::thread t(hack_start, game_data_dir);
    t.detach();
    return JNI_VERSION_1_6;
}
#endif
