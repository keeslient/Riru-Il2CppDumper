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

// 系统头文件
#include <sys/system_properties.h>
#include <sys/syscall.h>
#include <linux/unistd.h>

#define LOG_TAG "Perfare"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// =============================================================
// 1. 核心逻辑：寻找真正的 il2cpp 基址 (体积策略)
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
                            // 为了兼容性，size 使用 %lu 打印 unsigned long
                            LOGI("发现潜在目标 (Size: %lu MB): %s", size / 1024 / 1024, line);
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
// 2. 主线程逻辑
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
    // 验证偏移量 (Verify Offsets)
    // ---------------------------------------------------------
    
    uintptr_t offset_PacketEncode = 0x11b54c8; 
    
    void* target_addr = (void*)((uintptr_t)base_addr + offset_PacketEncode);
    
    LOGI("=================================================");
    LOGI(">>> 分析结果报告 <<<");
    LOGI("1. 真实基址: %p", base_addr);
    // 【修复】这里改成 %p，并强转为 void*，兼容 32/64 位
    LOGI("2. PacketEncode 偏移: %p", (void*)offset_PacketEncode);
    LOGI("3. PacketEncode 真实地址: %p", target_addr);
    LOGI("=================================================");
    LOGI(">>> (Hook 已暂停，因为缺少 Dobby 库，先验证地址是否正确) <<<");

    while(true) sleep(10);
}

// =============================================================
// 3. 固定模板代码 (NativeBridge & JNI入口)
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
            int fd = syscall(__NR_memfd_create, "anon", MFD_CLOEXEC);
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
