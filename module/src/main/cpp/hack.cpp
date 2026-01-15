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
#include <android/log.h>
#include <cstdlib>
#include <string>

#define LOG_TAG "IMO_NINJA"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// --- 1. 监控回调 ---
void universal_spy(void* instance, void* arg1) {
    LOGI("[🔥] 捕获到动作！实例: %p, 参数: %p", instance, arg1);
}

// --- 2. 手动 Hook 核心 ---
void manual_inline_hook(uintptr_t target_addr, void* new_func) {
    uintptr_t page_start = target_addr & ~0xFFF;
    if (mprotect((void*)page_start, 4096, PROT_READ | PROT_WRITE | PROT_EXEC) == 0) {
        uint32_t jmp_ins[] = {
            0x58000050, // LDR X16, #8
            0xd61f0200, // BR X16
            (uint32_t)((uintptr_t)new_func & 0xFFFFFFFF),
            (uint32_t)((uintptr_t)new_func >> 32)
        };
        memcpy((void*)target_addr, jmp_ins, sizeof(jmp_ins));
        __builtin___clear_cache((char*)target_addr, (char*)target_addr + sizeof(jmp_ins));
    }
}

// --- 3. 补全 Dumper 必须函数 ---
std::string GetLibDir(JavaVM *vms) {
    JNIEnv *env = nullptr;
    vms->AttachCurrentThread(&env, nullptr);
    jclass activity_thread_clz = env->FindClass("android/app/ActivityThread");
    if (activity_thread_clz) {
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
    uint32_t version; void *initialize;
    void *(*loadLibrary)(const char *libpath, int flag);
    void *(*getTrampoline)(void *handle, const char *name, const char *shorty, uint32_t len);
    void *isSupported; void *getAppEnv; void *isCompatibleWith; void *getSignalHandler;
    void *unloadLibrary; void *getError; void *isPathSupported; void *initAnonymousNamespace;
    void *createNamespace; void *linkNamespaces; void *(*loadLibraryExt)(const char *libpath, int flag, void *ns);
};

bool NativeBridgeLoad(const char *game_data_dir, int api_level, void *data, size_t length) {
    sleep(5);
    auto libart = dlopen("libart.so", RTLD_NOW);
    auto JNI_GetCreatedJavaVMs = (jint (*)(JavaVM **, jsize, jsize *)) dlsym(libart, "JNI_GetCreatedJavaVMs");
    JavaVM *vms_buf[1]; jsize num_vms;
    jint status = JNI_GetCreatedJavaVMs(vms_buf, 1, &num_vms);
    if (status != JNI_OK || num_vms <= 0) return false;
    JavaVM *vms = vms_buf[0];
    auto lib_dir = GetLibDir(vms);
    if (lib_dir.empty() || lib_dir.find("/lib/x86") != std::string::npos) return false;
    auto nb = dlopen("libhoudini.so", RTLD_NOW);
    if (!nb) nb = dlopen(GetNativeBridgeLibrary().data(), RTLD_NOW);
    if (nb) {
        auto callbacks = (NativeBridgeCallbacks *) dlsym(nb, "NativeBridgeItf");
        if (callbacks) {
            int fd = syscall(__NR_memfd_create, "anon", MFD_CLOEXEC);
            ftruncate(fd, (off_t) length);
            void *mem = mmap(nullptr, length, PROT_WRITE, MAP_SHARED, fd, 0);
            memcpy(mem, data, length); munmap(mem, length);
            char path[PATH_MAX]; snprintf(path, PATH_MAX, "/proc/self/fd/%d", fd);
            void *arm_handle = (api_level >= 26) ? callbacks->loadLibraryExt(path, RTLD_NOW, (void *) 3) : callbacks->loadLibrary(path, RTLD_NOW);
            if (arm_handle) {
                auto init = (void (*)(JavaVM *, void *)) callbacks->getTrampoline(arm_handle, "JNI_OnLoad", nullptr, 0);
                init(vms, (void *) game_data_dir);
                return true;
            }
        }
    }
    return false;
}

// --- 4. 核心启动逻辑 ---
void hack_start(const char *game_data_dir) {
    LOGI("[🚀] 启动【全网通】深度扫描...");
    for (int i = 0; i < 30; i++) {
        void *handle = xdl_open("libil2cpp.so", 0);
        if (handle) {
            // 1. 获取 il2cpp 官方解析器的地址
            void* resolve_addr = dlsym(handle, "il2cpp_resolve_icall");
            if (resolve_addr) {
                LOGI("[✅] 核心分发器已锁定: %p", resolve_addr);
                
                // 我们直接 Hook 这个分发器，看看游戏到底在偷偷调什么函数
                manual_inline_hook((uintptr_t)resolve_addr, (void*)universal_spy);
            }

            // 2. 同时在内存中搜索 "Send" 字符串相关的逻辑
            // ... (保持原本的 Dump 逻辑，让我们看看 dump.cs 是否有变动) ...

            il2cpp_api_init(handle);
            il2cpp_dump(game_data_dir);
            break;
        }
        sleep(1);
    }
}

void hack_prepare(const char *game_data_dir, void *data, size_t length) {
    LOGI("======================================");
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
