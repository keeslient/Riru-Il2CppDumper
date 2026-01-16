//
// Created by Perfare on 2020/7/4.
// Modified for LIAPP detection & Log Filtering
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

// =================【新增功能 1：防刷屏过滤器】=================
#include <map>
#include <mutex>
#include <ctime>

static std::map<void*, int> g_HitCounts;
static std::map<void*, time_t> g_HitTimes;
static std::mutex g_SpamMutex;

// 可以在其他文件中调用的过滤器
// true = 噪音(屏蔽) | false = 新数据(放行)
bool IsSpam(void *address) {
    std::lock_guard<std::mutex> lock(g_SpamMutex);
    time_t now = time(nullptr);

    // 如果是新地址或超时5秒，重置
    if (g_HitTimes.find(address) == g_HitTimes.end() || (now - g_HitTimes[address] > 5)) {
        g_HitCounts[address] = 1;
        g_HitTimes[address] = now;
        return false;
    }

    // 5秒内
    g_HitCounts[address]++;
    if (g_HitCounts[address] > 5) {
        return true; // 超过5次屏蔽
    }
    return false;
}

// =================【新增功能 2：内存模块遍历】=================
#include <link.h>

// 回调函数：打印加载的库信息
static int print_libs_callback(struct dl_phdr_info* info, size_t size, void* data) {
    // 只打印包含特定关键词的路径，或者是应用私有目录下的库，减少日志垃圾
    // 这里的关键词你可以根据实际情况增加
    if (info->dlpi_name && (
            strstr(info->dlpi_name, "com.") || 
            strstr(info->dlpi_name, "/data/") || 
            strstr(info->dlpi_name, "il2cpp") || 
            strstr(info->dlpi_name, "liapp") || 
            strstr(info->dlpi_name, "unity"))) {
        
        LOGI("[🔍 发现模块] Name: %s | Base Address: %p", 
             (strlen(info->dlpi_name) > 0 ? info->dlpi_name : "只读/匿名段(Anonymous)"), 
             (void*)info->dlpi_addr);
    }
    return 0;
}
// ============================================================

void hack_start(const char *game_data_dir) {
    // 1. 启动时先打印一遍内存里到底加载了谁，这步很关键！
    LOGI("========== [START] Module Scan ==========");
    dl_iterate_phdr(print_libs_callback, nullptr);
    LOGI("========== [ END ] Module Scan ==========");

    bool load = false;
    void *handle = nullptr;

    for (int i = 0; i < 10; i++) {
        // 策略A: 优先尝试打开 libliapp.so (既然字符串里有它，内存里可能有)
        handle = xdl_open("libliapp.so", 0);
        if (handle) {
            LOGI("!!! 成功定位到 libliapp.so !!! Base: %p", handle);
            load = true;
            // 拿到句柄后，尝试初始化
            il2cpp_api_init(handle);
            il2cpp_dump(game_data_dir);
            break;
        }

        // 策略B: 回退尝试 libil2cpp.so (可能是诱饵，也可能是真的)
        handle = xdl_open("libil2cpp.so", 0);
        if (handle) {
            LOGI("定位到 libil2cpp.so (可能是壳/诱饵) Base: %p", handle);
            load = true;
            il2cpp_api_init(handle);
            il2cpp_dump(game_data_dir);
            break;
        } 
        
        sleep(1);
    }

    if (!load) {
        LOGI("Target SO (libil2cpp/libliapp) not found in thread %d", gettid());
    }
}

// 下面的代码保持原样，未做逻辑修改，仅保留完整性
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
