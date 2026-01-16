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
// 【新增】我们需要这个头文件来遍历内存模块
#include <link.h>

// 【新增】回调函数：打印当前加载的所有模块
// 这样我们就能在 Logcat 里看到到底有哪些 SO 被加载了，以及它们的真实地址
static int print_libs_callback(struct dl_phdr_info* info, size_t size, void* data) {
    // 过滤一下，只显示我们关心的（包含 com. 或者 data 路径，或者名字里带 il2cpp/liapp 的）
    if (info->dlpi_name && (
            strstr(info->dlpi_name, "com.") || 
            strstr(info->dlpi_name, "/data/") || 
            strstr(info->dlpi_name, "il2cpp") || 
            strstr(info->dlpi_name, "liapp") || 
            strstr(info->dlpi_name, "unity"))) {
        
        LOGI("[🔍 发现模块] Name: %s | Base Address: %p", 
             (strlen(info->dlpi_name) > 0 ? info->dlpi_name : "可能是匿名段(Anonymous)"), 
             (void*)info->dlpi_addr);
    }
    return 0;
}

void hack_start(const char *game_data_dir) {
    // 1. 一上来先吼一声，证明代码跑起来了
    LOGI(">>> HACK START: 正在扫描内存模块... <<<");
    
    // 2. 打印所有模块，请在日志里搜 "发现模块"
    dl_iterate_phdr(print_libs_callback, nullptr);
    LOGI(">>> 扫描结束，开始寻找目标 SO <<<");

    bool load = false;
    void *handle = nullptr;

    // 3. 循环寻找目标，优先找 libliapp.so
    for (int i = 0; i < 15; i++) { // 多试几次，给它点加载时间
        
        // --- 尝试 A: 找 libliapp.so ---
        handle = xdl_open("libliapp.so", 0);
        if (handle) {
            LOGI("!!! 成功定位到 libliapp.so !!! Base: %p", handle);
            load = true;
            // 找到真身后，直接开始 Dump
            il2cpp_api_init(handle);
            il2cpp_dump(game_data_dir);
            break;
        }

        // --- 尝试 B: 找 libil2cpp.so (保底) ---
        // 如果这里打印出来了，说明至少找到了诱饵
        void* temp_handle = xdl_open("libil2cpp.so", 0);
        if (temp_handle) {
             LOGI(">>> 发现 libil2cpp.so (可能是壳) Base: %p", temp_handle);
             // 先不急着 break，继续循环看看能不能等到 liapp 出现
             // 如果你确定只要 il2cpp，可以把下面两行注释解开
             // handle = temp_handle;
             // load = true; break;
        }

        sleep(1);
    }
    
    // 如果最后还是没找到 liapp，但找到了 il2cpp，那就用 il2cpp 兜底
    if (!load && !handle) {
        handle = xdl_open("libil2cpp.so", 0);
        if (handle) {
            LOGI(">>> 最终回退使用 libil2cpp.so <<<");
            load = true;
            il2cpp_api_init(handle);
            il2cpp_dump(game_data_dir);
        }
    }

    if (!load) {
        LOGI("FATAL: 真的找不到了 (Target SO not found) thread %d", gettid());
    }
}

// -----------------------------------------------------------
// 以下代码未修改，保持原样
// -----------------------------------------------------------

std::string GetLibDir(JavaVM *vms) {
    JNIEnv *env = nullptr;
    vms->AttachCurrentThread(&env, nullptr);
    jclass activity_thread_clz = env->FindClass("android/app/ActivityThread");
    if (activity_thread_clz != nullptr) {
        jmethodID currentApplicationId = env->GetStaticMethodID(activity_thread_clz,
                                                                "currentApplication",
                                                                "()Landroid/app/Application;");
        if (currentApplicationId) {
            jobject application = env->CallStaticObjectMethod(activity_thread_clz,
                                                              currentApplicationId);
            jclass application_clazz = env->GetObjectClass(application);
            if (application_clazz) {
                jmethodID get_application_info = env->GetMethodID(application_clazz,
                                                                  "getApplicationInfo",
                                                                  "()Landroid/content/pm/ApplicationInfo;");
                if (get_application_info) {
                    jobject application_info = env->CallObjectMethod(application,
                                                                     get_application_info);
                    jfieldID native_library_dir_id = env->GetFieldID(
                            env->GetObjectClass(application_info), "nativeLibraryDir",
                            "Ljava/lang/String;");
                    if (native_library_dir_id) {
                        auto native_library_dir_jstring = (jstring) env->GetObjectField(
                                application_info, native_library_dir_id);
                        auto path = env->GetStringUTFChars(native_library_dir_jstring, nullptr);
                        LOGI("lib dir %s", path);
                        std::string lib_dir(path);
                        env->ReleaseStringUTFChars(native_library_dir_jstring, path);
                        return lib_dir;
                    } else {
                        LOGE("nativeLibraryDir not found");
                    }
                } else {
                    LOGE("getApplicationInfo not found");
                }
            } else {
                LOGE("application class not found");
            }
        } else {
            LOGE("currentApplication not found");
        }
    } else {
        LOGE("ActivityThread not found");
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
    //TODO 等待houdini初始化
    sleep(5);

    auto libart = dlopen("libart.so", RTLD_NOW);
    auto JNI_GetCreatedJavaVMs = (jint (*)(JavaVM **, jsize, jsize *)) dlsym(libart,
                                                                             "JNI_GetCreatedJavaVMs");
    LOGI("JNI_GetCreatedJavaVMs %p", JNI_GetCreatedJavaVMs);
    JavaVM *vms_buf[1];
    JavaVM *vms;
    jsize num_vms;
    jint status = JNI_GetCreatedJavaVMs(vms_buf, 1, &num_vms);
    if (status == JNI_OK && num_vms > 0) {
        vms = vms_buf[0];
    } else {
        LOGE("GetCreatedJavaVMs error");
        return false;
    }

    auto lib_dir = GetLibDir(vms);
    if (lib_dir.empty()) {
        LOGE("GetLibDir error");
        return false;
    }
    if (lib_dir.find("/lib/x86") != std::string::npos) {
        LOGI("no need NativeBridge");
        munmap(data, length);
        return false;
    }

    auto nb = dlopen("libhoudini.so", RTLD_NOW);
    if (!nb) {
        auto native_bridge = GetNativeBridgeLibrary();
        LOGI("native bridge: %s", native_bridge.data());
        nb = dlopen(native_bridge.data(), RTLD_NOW);
    }
    if (nb) {
        LOGI("nb %p", nb);
        auto callbacks = (NativeBridgeCallbacks *) dlsym(nb, "NativeBridgeItf");
        if (callbacks) {
            LOGI("NativeBridgeLoadLibrary %p", callbacks->loadLibrary);
            LOGI("NativeBridgeLoadLibraryExt %p", callbacks->loadLibraryExt);
            LOGI("NativeBridgeGetTrampoline %p", callbacks->getTrampoline);

            int fd = syscall(__NR_memfd_create, "anon", MFD_CLOEXEC);
            ftruncate(fd, (off_t) length);
            void *mem = mmap(nullptr, length, PROT_WRITE, MAP_SHARED, fd, 0);
            memcpy(mem, data, length);
            munmap(mem, length);
            munmap(data, length);
            char path[PATH_MAX];
            snprintf(path, PATH_MAX, "/proc/self/fd/%d", fd);
            LOGI("arm path %s", path);

            void *arm_handle;
            if (api_level >= 26) {
                arm_handle = callbacks->loadLibraryExt(path, RTLD_NOW, (void *) 3);
            } else {
                arm_handle = callbacks->loadLibrary(path, RTLD_NOW);
            }
            if (arm_handle) {
                LOGI("arm handle %p", arm_handle);
                auto init = (void (*)(JavaVM *, void *)) callbacks->getTrampoline(arm_handle,
                                                                                  "JNI_OnLoad",
                                                                                  nullptr, 0);
                LOGI("JNI_OnLoad %p", init);
                init(vms, (void *) game_data_dir);
                return true;
            }
            close(fd);
        }
    }
    return false;
}

void hack_prepare(const char *game_data_dir, void *data, size_t length) {
    LOGI("hack thread: %d", gettid());
    int api_level = android_get_device_api_level();
    LOGI("api level: %d", api_level);

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
