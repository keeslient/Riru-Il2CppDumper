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

// ------------------------------------------------------------------
// 直接从 maps 读取基地址 (专门找 libil2cpp.so)
// ------------------------------------------------------------------
void* GetIl2CppBase() {
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return nullptr;

    char line[2048];
    void* addr = nullptr;

    while (fgets(line, sizeof(line), fp)) {
        // 只要行里包含 "libil2cpp.so" 且是可执行段 (r-xp)
        if (strstr(line, "libil2cpp.so") && strstr(line, "r-xp")) {
            unsigned long start_addr;
            if (sscanf(line, "%lx-", &start_addr) == 1) {
                addr = (void*)start_addr;
                // 这里可以顺便打印一下找到的行，确认是不是那个大文件
                __android_log_print(ANDROID_LOG_INFO, "Perfare", "Maps Found: %s", line);
                break;
            }
        }
    }
    fclose(fp);
    return addr;
}

// ------------------------------------------------------------------
// 主逻辑
// ------------------------------------------------------------------
void hack_start(const char *game_data_dir) {
    __android_log_print(ANDROID_LOG_INFO, "Perfare", ">>> HACK START: 正在等待真正的 libil2cpp.so 加载... <<<");

    void* base_addr = nullptr;
    
    // 死循环等待，LIAPP 解密需要时间，我们就在这等它解密完
    while (true) {
        base_addr = GetIl2CppBase();
        
        if (base_addr != nullptr) {
            __android_log_print(ANDROID_LOG_INFO, "Perfare", "!!! 捕获真身 !!! libil2cpp Base: %p", base_addr);
            break;
        }
        
        sleep(1);
    }

    // ---------------------------------------------------------
    // 这里的偏移量一定要用你 dump.cs 里的！
    // ---------------------------------------------------------
    
    // 例如 PacketEncode 的 RVA 是 0x11b54c8 (根据你之前的描述)
    // 真实地址 = base_addr + 0x11b54c8
    
    // uintptr_t offset = 0x11b54c8; 
    // void* target_addr = (void*)((uintptr_t)base_addr + offset);
    
    // __android_log_print(ANDROID_LOG_INFO, "Perfare", ">>> Hook 点已就绪: %p <<<", target_addr);

    // 在这里执行 DobbyHook ...
    
    while(true) sleep(10);
}

// 下面的 NativeBridgeLoad / JNI_OnLoad 保持原样...

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
