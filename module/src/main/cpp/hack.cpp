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

// --- 工具函数：获取模块基址 ---
uintptr_t get_module_base(const char* name) {
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return 0;
    char line[1024];
    uintptr_t start = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, name)) {
            start = (uintptr_t)strtoull(line, nullptr, 16);
            break;
        }
    }
    fclose(fp);
    return start;
}

// --- 核心：内存镜像 Dump 函数 ---
// 只要能读到内存，就能把它导出来分析，绕过所有 Hook 检测
void dump_memory_mirror(const char* so_name, const char* out_name) {
    uintptr_t base = get_module_base(so_name);
    if (!base) return;

    LOGI("[📡] 发现目标库 %s，基址: %p，准备抄家...", so_name, (void*)base);

    // 假设乱码库大小 4MB，我们 Dump 8MB 确保万无一失
    size_t dump_size = 8 * 1024 * 1024; 
    char path[256];
    // 存放在游戏私有目录，避免权限问题
    sprintf(path, "/sdcard/Android/data/com.com2us.imo.normal.freefull.google.global.android.common/files/%s", out_name);

    FILE* fp = fopen(path, "wb");
    if (fp) {
        // 使用最稳妥的 fwrite 读内存
        fwrite((void*)base, 1, dump_size, fp);
        fclose(fp);
        LOGI("[✅] 抄家成功！镜像已保存至: %s", path);
        LOGI("[💡] 请将此文件拉到电脑，搜索你的 Wireshark 特征码或分析 SVC 指令");
    } else {
        LOGI("[❌] 导出失败，请检查 SD 卡权限或目录是否存在");
    }
}

// --- 补全 Dumper 必要函数 ---
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
                        auto jstr = (jstring) env->GetObjectField(application_info, native_library_dir_id);
                        auto path = env->GetStringUTFChars(jstr, nullptr);
                        std::string res(path);
                        env->ReleaseStringUTFChars(jstr, path);
                        return res;
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
    ::sleep(5);
    auto libart = dlopen("libart.so", RTLD_NOW);
    auto JNI_GetCreatedJavaVMs = (jint (*)(JavaVM **, jsize, jsize *)) dlsym(libart, "JNI_GetCreatedJavaVMs");
    JavaVM *vms_buf[1]; jsize num_vms;
    jint status = JNI_GetCreatedJavaVMs(vms_buf, 1, &num_vms);
    if (status != JNI_OK || num_vms <= 0) return false;
    JavaVM *vms = vms_buf[0];
    auto lib_dir = GetLibDir(vms);
    if (lib_dir.empty() || lib_dir.find("/lib/x86") != std::string::npos) return false;
    auto nb = ::dlopen("libhoudini.so", RTLD_NOW);
    if (!nb) nb = ::dlopen(GetNativeBridgeLibrary().data(), RTLD_NOW);
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

// --- 5. 核心启动逻辑 ---
// 在 hack_start 里加入这段智能扫描代码
void hack_start(const char *game_data_dir) {
    LOGI("[🚀] 智能抄家模式启动...");
    
    for (int i = 0; i < 60; i++) {
        // 自动寻找那个“乱码 SO”
        FILE* fp = fopen("/proc/self/maps", "r");
        if (fp) {
            char line[1024];
            while (fgets(line, sizeof(line), fp)) {
                // 特征码过滤：找那些在 /data/app 目录下，但不是 libmain、libunity、libil2cpp 的 .so
                if (strstr(line, ".so") && strstr(line, "/data/app") && 
                    !strstr(line, "libmain.so") && !strstr(line, "libunity.so") && 
                    !strstr(line, "libil2cpp.so") && !strstr(line, "libreal.so")) {
                    
                    // 提取这个可疑 SO 的名字
                    char* so_path = strchr(line, '/');
                    char* so_name = strrchr(so_path, '/');
                    if (so_name) {
                        so_name++; // 跳过 '/'
                        // 去掉换行符
                        so_name[strcspn(so_name, "\n")] = 0;
                        
                        LOGI("[🎯] 发现可疑 LIAPP 核心库: %s", so_name);
                        dump_memory_mirror(so_name, "liapp_core_auto.bin");
                    }
                }
            }
            fclose(fp);
        }

        // 同时检查 il2cpp
        void *handle = xdl_open("libil2cpp.so", 0);
        if (handle) {
            LOGI("[✅] libil2cpp 已加载，常规 Dump 启动...");
            il2cpp_api_init(handle);
            il2cpp_dump(game_data_dir);
            break; 
        }
        ::sleep(2);
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
