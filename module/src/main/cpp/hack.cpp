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
#include <fstream>  // 必须包含
#include <cstdlib>  // strtoul

// ------------------------------------------------------------------
// 核心函数：绕过 xdl，直接从内核 maps 读取基地址
// ------------------------------------------------------------------
void* GetBaseAddress(const char* lib_name) {
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return nullptr;

    char line[2048];
    void* addr = nullptr;

    while (fgets(line, sizeof(line), fp)) {
        // 查找包含 lib_name (例如 libfvctyud.so) 且具有 r-xp (可执行) 权限的行
        if (strstr(line, lib_name) && strstr(line, "r-xp")) {
            // maps 格式: 78fac8f000-78fad24000 r-xp ...
            // 我们只需要第一个横杠前面的部分
            unsigned long start_addr;
            if (sscanf(line, "%lx-", &start_addr) == 1) {
                addr = (void*)start_addr;
                break;
            }
        }
    }
    fclose(fp);
    return addr;
}

void hack_start(const char *game_data_dir) {
    __android_log_print(ANDROID_LOG_INFO, "Perfare", ">>> HACK START: Waiting for libfvctyud.so via Maps... <<<");

    void* base_addr = nullptr;
    
    // 1. 死循环等待，直到 maps 里出现这个库
    while (true) {
        base_addr = GetBaseAddress("libfvctyud.so"); // 直接找这个名字
        
        if (base_addr != nullptr) {
            __android_log_print(ANDROID_LOG_INFO, "Perfare", "!!! SUCCESS !!! Real Base Address: %p", base_addr);
            break;
        }
        
        // 没找到就睡 1 秒
        sleep(1);
    }

    // 2. 拿到基址后，你需要做的 Hook 操作放这里
    // 注意：不要再调 il2cpp_api_init 了，那个肯定崩。
    
    // 示例：打印一下验证偏移 (假设偏移是 0x123456)
    // __android_log_print(ANDROID_LOG_INFO, "Perfare", "Target Func Addr: %p", (void*)((uintptr_t)base_addr + 0x123456));

    // ---------------------------------------------------------
    // 你的业务代码 (Hook Dobby 等) 写在下面
    // ---------------------------------------------------------
    
    
    // ---------------------------------------------------------

    __android_log_print(ANDROID_LOG_INFO, "Perfare", ">>> Hook Setup Done. Monitoring... <<<");
    
    // 保持线程存活
    while(true) sleep(10);
}

// ------------------------------------------------------------------
// 下面的 NativeBridgeLoad 等保持原样，为了过编译我不删了
// ------------------------------------------------------------------

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
