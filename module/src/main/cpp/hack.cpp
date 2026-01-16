#include "hack.h"
#include "log.h"
#include "xdl.h"
#include <cstring>
#include <cstdio>
#include <unistd.h>
#include <dlfcn.h>
#include <jni.h>
#include <thread>
#include <sys/mman.h>
#include <android/log.h>
#include <fstream>
#include <cstdlib>
#include <vector>
#include <iomanip>
#include <sstream>
#include <string>
#include <array>
#include <link.h>

// 【修复】补回缺失的系统头文件
#include <sys/system_properties.h> // 解决 PROP_VALUE_MAX 报错
#include <sys/syscall.h>           // 解决 syscall 报错
#include <linux/unistd.h>          // 解决 __NR_memfd_create 报错

// =============================================================
// 0. 基础设置与防报错声明
// =============================================================

#define LOG_TAG "Perfare"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// 手动声明 DobbyHook
extern "C" {
    int DobbyHook(void *address, void *replace_call, void **origin_call);
}

// =============================================================
// 1. 辅助工具：Hex 转字符串
// =============================================================
std::string hexStr(unsigned char *data, int len) {
    std::stringstream ss;
    ss << std::hex;
    for (int i = 0; i < len; ++i)
        ss << std::setw(2) << std::setfill('0') << (int)data[i] << " ";
    return ss.str();
}

// =============================================================
// 2. Hook 函数定义
// =============================================================

// 原始函数指针
void (*old_PacketEncode)(void* instance, void* packet, bool flag);

// 我们的新函数
void new_PacketEncode(void* instance, void* packet, bool flag) {
    LOGI(">>> [PacketEncode] 触发! Obj: %p, Flag: %d", packet, flag);
    
    // 必须调用原函数
    if(old_PacketEncode) old_PacketEncode(instance, packet, flag);
}

// =============================================================
// 3. 核心逻辑：寻找真正的 il2cpp 基址 (体积策略)
// =============================================================
void* FindRealIl2CppBase() {
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return nullptr;

    char line[2048];
    void* best_addr = nullptr;
    unsigned long max_size = 0;

    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "r-xp")) {
            if (strstr(line, "/data/app") && strstr(line, ".so")) {
                
                // 排除已知非目标
                if (strstr(line, "libunity.so") || 
                    strstr(line, "libmain.so") || 
                    strstr(line, "base.odex") || 
                    strstr(line, "webview")) continue;

                unsigned long start, end;
                if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
                    unsigned long size = end - start;
                    
                    // 寻找大于 30MB 的段
                    if (size > 1024 * 1024 * 30) { 
                        if (size > max_size) {
                            max_size = size;
                            best_addr = (void*)start;
                            LOGI("发现潜在目标 (Size: %lu bytes): %s", size, line);
                        }
                    }
                }
            }
        }
    }
    fclose(fp);
    return best_addr;
}

// =============================================================
// 4. 主线程逻辑
// =============================================================
void hack_start(const char *game_data_dir) {
    LOGI(">>> HACK START: 正在寻找真正的 il2cpp 大文件... <<<");

    void* base_addr = nullptr;
    
    while (true) {
        base_addr = FindRealIl2CppBase();
        if (base_addr != nullptr) {
            LOGI("!!! 锁定真身 !!! Base Address: %p", base_addr);
            break;
        }
        sleep(1);
    }

    // ---------------------------------------------------------
    // 执行 Hook (偏移量来自 dump.cs)
    // ---------------------------------------------------------
    uintptr_t offset_PacketEncode = 0x11b54c8; 
    void* target_addr = (void*)((uintptr_t)base_addr + offset_PacketEncode);
    
    LOGI(">>> 准备 Hook 地址: %p (Base+0x%lx) <<<", target_addr, offset_PacketEncode);

    int ret = DobbyHook(target_addr, (void*)new_PacketEncode, (void**)&old_PacketEncode);
    if (ret == 0) {
        LOGI(">>> DobbyHook 返回成功! 监控中... <<<");
    } else {
        LOGI(">>> DobbyHook 失败，返回值: %d <<<", ret);
    }
    
    while(true) sleep(10);
}

// =============================================================
// 5. 固定模板代码 (NativeBridge & JNI入口) - 已包含所需头文件
// =============================================================

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
    auto value = std::array<char, PROP_VALUE_MAX>(); // 这里之前报错，现在修复了
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
    if (status != JNI_OK || num_vms <= 0) return false;
    
    JavaVM *vms = vms_buf[0];
    auto lib_dir = GetLibDir(vms);
    if (lib_dir.empty() || lib_dir.find("/lib/x86") != std::string::npos) {
        munmap(data, length);
        return false;
    }

    auto nb = dlopen("libhoudini.so", RTLD_NOW);
    if (!nb) {
        auto native_bridge = GetNativeBridgeLibrary();
        nb = dlopen(native_bridge.data(), RTLD_NOW);
    }
    if (nb) {
        auto callbacks = (NativeBridgeCallbacks *) dlsym(nb, "NativeBridgeItf");
        if (callbacks) {
            int fd = syscall(__NR_memfd_create, "anon", MFD_CLOEXEC); // 这里之前报错，现在修复了
            ftruncate(fd, (off_t) length);
            void *mem = mmap(nullptr, length, PROT_WRITE, MAP_SHARED, fd, 0);
            memcpy(mem, data, length);
            munmap(mem, length);
            munmap(data, length);
            char path[PATH_MAX];
            snprintf(path, PATH_MAX, "/proc/self/fd/%d", fd);
            void *arm_handle;
            if (api_level >= 26) {
                arm_handle = callbacks->loadLibraryExt(path, RTLD_NOW, (void *) 3);
            } else {
                arm_handle = callbacks->loadLibrary(path, RTLD_NOW);
            }
            if (arm_handle) {
                auto init = (void (*)(JavaVM *, void *)) callbacks->getTrampoline(arm_handle, "JNI_OnLoad", nullptr, 0);
                init(vms, (void *) game_data_dir);
                return true;
            }
            close(fd);
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
    std::thread hack_thread(hack_start, game_data_dir);
    hack_thread.detach();
    return JNI_VERSION_1_6;
}
#endif
