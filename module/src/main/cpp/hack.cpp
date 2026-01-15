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
#include <sys/socket.h>

#define LOG_TAG "IMO_NINJA"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// --- 补全缺失的工具函数 ---
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

// --- 1. 底层 Socket 拦截 (针对 libc) ---
// 如果 il2cpp 层的 RVA 没反应，这个绝对有反应
ssize_t (*old_sendto)(int, const void *, size_t, int, const struct sockaddr *, socklen_t);

ssize_t new_sendto(int s, const void *buf, size_t len, int flags, const struct sockaddr *to, socklen_t tolen) {
    if (len > 5) { // 过滤微小的心跳包
        LOGI("[📡] 底层 Socket 拦截成功! 长度: %zu", len);
        unsigned char* p = (unsigned char*)buf;
        char hex_buf[64] = {0};
        for(int i=0; i<16 && i<len; i++) sprintf(hex_buf + strlen(hex_buf), "%02X ", p[i]);
        LOGI("[📦] 发送数据头: %s", hex_buf);
    }
    return old_sendto(s, buf, len, flags, to, tolen);
}

// --- 2. 业务层监控回调 ---
void universal_spy(void* instance, void* arg1) {
    LOGI("[🔥] 业务层命中！实例: %p, 参数(可能是Packet): %p", instance, arg1);
}

// --- 3. 手动 Hook 核心 (ARM64) ---
void manual_inline_hook(uintptr_t target_addr, void* new_func, void** old_func_ptr = nullptr) {
    uintptr_t page_start = target_addr & ~0xFFF;
    if (mprotect((void*)page_start, 4096, PROT_READ | PROT_WRITE | PROT_EXEC) == 0) {
        if (old_func_ptr) *old_func_ptr = (void*)target_addr; 
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

// --- 4. 补全 Dumper 辅助函数 ---
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
void hack_start(const char *game_data_dir) {
    LOGI("[🚀] 忍者全家桶 + 底层 Socket 最终布控...");

    // 方案 A: 拦截系统底层 Socket
    void* libc_handle = dlopen("libc.so", RTLD_NOW);
    if (libc_handle) {
        void* sendto_addr = dlsym(libc_handle, "sendto");
        if (sendto_addr) {
            manual_inline_hook((uintptr_t)sendto_addr, (void*)new_sendto, (void**)&old_sendto);
            LOGI("[✅] 系统级监控 (libc.sendto) 部署成功");
        }
    }

    // 方案 B: 拦截业务层 (依据最新 dump.cs)
    for (int i = 0; i < 30; i++) {
        void *handle = xdl_open("libil2cpp.so", 0);
        if (handle) {
            uintptr_t base = get_module_base("libil2cpp.so");
            if (base) {
                LOGI("[✅] 基址锁定: %p，业务布控开始...", (void*)base);

                // 根据最新 dump.cs 地址
                manual_inline_hook(base + 0x948D40, (void*)universal_spy); // SendPacket
                manual_inline_hook(base + 0x948FB0, (void*)universal_spy); // ProcessSend
                manual_inline_hook(base + 0x94FE00, (void*)universal_spy); // PacketEncrypt
                manual_inline_hook(base + 0x9497A0, (void*)universal_spy); // OnSend
                
                // 实时心跳监控
                std::thread([base]() {
                    while (true) {
                        unsigned char* pc = (unsigned char*)(base + 0x94FE00);
                        LOGI("[🔍] 心跳(Encrypt): %02X %02X %02X %02X", pc[0], pc[1], pc[2], pc[3]);
                        ::sleep(10); 
                    }
                }).detach();
            }
            il2cpp_api_init(handle);
            il2cpp_dump(game_data_dir);
            break;
        }
        ::sleep(1);
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
