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
#include <signal.h>
#include <ucontext.h>

#define LOG_TAG "IMO_NINJA"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// --- 陷阱配置区 ---
static uintptr_t global_sbox_addr = 0;
static uintptr_t global_so_base = 0;
static const uintptr_t SBOX_OFFSET = 0x89F90; // AES S-Box 偏移

// --- 1. 信号处理函数 (捕兽夹核心) ---
// --- 1. 信号处理函数 (适配 32/64 位) ---
void sbox_trap_handler(int sig, siginfo_t *info, void *context) {
    auto* ctx = (ucontext_t*)context;
    uintptr_t pc = 0;

    LOGI("================ [🚨 捕获加密动作] ================");

#if defined(__aarch64__)
    // 64 位模式
    pc = ctx->uc_mcontext.pc;
    uintptr_t relative_pc = pc - global_so_base;
    LOGI("[🎯] 触发指令偏移 (PC): 0x%lx (64-bit)", (long)relative_pc);
    
    for(int i = 0; i < 8; i++) {
        LOGI("[💎] 寄存器 X%d: 0x%llx", i, (unsigned long long)ctx->uc_mcontext.regs[i]);
    }
#elif defined(__arm__)
    // 32 位模式 (armeabi-v7a)
    pc = ctx->uc_mcontext.arm_pc;
    uintptr_t relative_pc = pc - global_so_base;
    LOGI("[🎯] 触发指令偏移 (PC): 0x%lx (32-bit)", (long)relative_pc);
    
    // 32 位常用寄存器是 R0-R7
    LOGI("[💎] R0: 0x%lx, R1: 0x%lx, R2: 0x%lx, R3: 0x%lx", 
         ctx->uc_mcontext.arm_r0, ctx->uc_mcontext.arm_r1, 
         ctx->uc_mcontext.arm_r2, ctx->uc_mcontext.arm_r3);
#endif

    // 必须恢复读取权限
    mprotect((void*)(global_sbox_addr & ~0xFFF), 4096, PROT_READ);
    LOGI("[✅] 权限已临时恢复。");
    LOGI("==================================================");
}

// --- 2. 抄家辅助：获取模块基址 ---
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

// --- 3. 核心：抄家并布阵 ---
void dump_and_trap(const char* so_name, const char* game_data_dir) {
    uintptr_t base = get_module_base(so_name);
    if (!base) return;

    global_so_base = base;
    LOGI("[📡] 锁定目标 %s，基址: %p", so_name, (void*)base);

    // 执行 Dump
    size_t dump_size = 8 * 1024 * 1024; 
    char path[256];
    sprintf(path, "%s/%s.bin", game_data_dir, "liapp_core_auto");
    
    FILE* fp = fopen(path, "wb");
    if (fp) {
        fwrite((void*)base, 1, dump_size, fp);
        fclose(fp);
        LOGI("[✅] 抄家成功: %s", path);
    }

    // 布下陷阱
    global_sbox_addr = base + SBOX_OFFSET;
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = sbox_trap_handler;
    sigaction(SIGSEGV, &sa, NULL);

    mprotect((void*)(global_sbox_addr & ~0xFFF), 4096, PROT_NONE);
    LOGI("[🪤] AES 陷阱已布在 %s 偏移 0x%lx 处", so_name, (long)SBOX_OFFSET);
}

// --- 以下为官方原版逻辑，保持不变 ---

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
    void *isSupported; void *getAppEnv; void *isCompatibleWith; void *getSignalHandler;
    void *unloadLibrary; void *getError; void *isPathSupported; void *initAnonymousNamespace;
    void *createNamespace; void *linkNamespaces;
    void *(*loadLibraryExt)(const char *libpath, int flag, void *ns);
};

// 官方原版 hack_start
void hack_start(const char *game_data_dir) {
    LOGI("[🚀] 整合版注入成功，等待 libil2cpp...");
    bool trap_done = false;

    for (int i = 0; i < 60; i++) {
        FILE* fp = fopen("/proc/self/maps", "r");
        if (fp) {
            char line[1024];
            while (fgets(line, sizeof(line), fp)) {
                // 修改点：精准锁定 libfvctyud.so (或者你确定的乱码名)
                // 只有名字匹配时才布阵，布完阵立刻把 trap_done 设为 true
                if (!trap_done && strstr(line, "libfvctyud.so") && strstr(line, "/data/app")) {
                    char* so_path = strchr(line, '/');
                    char* so_name = strrchr(so_path, '/');
                    if (so_name) {
                        so_name++;
                        so_name[strcspn(so_name, "\n")] = 0;
                        
                        // 只针对这个核心库布阵
                        dump_and_trap(so_name, game_data_dir);
                        trap_done = true; // 标记已完成，不再对其他 SO 布阵
                        LOGI("[🔥] 目标锁定，陷阱已布下，停止扫描其他库。");
                    }
                }
            }
            fclose(fp);
        }

        // 检查 il2cpp 是否加载，加载了就说明游戏进入主逻辑了
        void *handle = xdl_open("libil2cpp.so", 0);
        if (handle) {
            il2cpp_api_init(handle);
            il2cpp_dump(game_data_dir);
            // 如果陷阱还没布下，这里可以做最后的兜底，但通常上面已经完成了
            break; 
        }
        ::sleep(2);
    }
}

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
    if (!nb) nb = dlopen(GetNativeBridgeLibrary().data(), RTLD_NOW);
    
    if (nb) {
        auto callbacks = (NativeBridgeCallbacks *) dlsym(nb, "NativeBridgeItf");
        if (callbacks) {
            int fd = syscall(__NR_memfd_create, "anon", MFD_CLOEXEC);
            ftruncate(fd, (off_t) length);
            void *mem = mmap(nullptr, length, PROT_WRITE, MAP_SHARED, fd, 0);
            memcpy(mem, data, length); munmap(mem, length); munmap(data, length);
            char path[PATH_MAX]; snprintf(path, PATH_MAX, "/proc/self/fd/%d", fd);
            
            void *arm_handle = (api_level >= 26) ? callbacks->loadLibraryExt(path, RTLD_NOW, (void *) 3) : callbacks->loadLibrary(path, RTLD_NOW);
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
    // 关键修正：确保异步线程不会丢失 reserved 里的路径
    std::string data_dir = reserved ? (const char *) reserved : "";
    std::thread([data_dir]() {
        hack_start(data_dir.c_str());
    }).detach();
    return JNI_VERSION_1_6;
}
#endif
