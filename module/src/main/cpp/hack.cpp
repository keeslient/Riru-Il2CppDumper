#include "hack.h"
#include "il2cpp_dump.h"
#include "log.h"
#include "xdl.h"
#include "shadowhook.h" 
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
#include <iomanip>
#include <sstream>

// --- 1. 定义 Hook 相关的全局变量 ---
typedef void* (*PacketEncode_t)(void* instance, void* packet, char a3);
PacketEncode_t old_PacketEncode = nullptr;

// 辅助工具：将字节数组转为十六进制字符串打印
std::string bytesToHex(uint8_t* data, uint32_t len) {
    if (!data || len == 0) return "Empty";
    std::stringstream ss;
    for (uint32_t i = 0; i < len; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i] << " ";
    }
    return ss.str();
}

// --- 2. 核心：封包拦截 Hook 函数 ---
void* new_PacketEncode(void* instance, void* packet, char a3) {
    if (packet != nullptr) {
        // 按照之前的 sub 函数分析提取数据
        uintptr_t* stream_ptr = (uintptr_t*)((uintptr_t)packet + 0x10);
        
        if (stream_ptr && (uintptr_t)*stream_ptr > 0x100000) {
            uintptr_t* array_ptr = (uintptr_t*)(*stream_ptr + 0x10);
            
            if (array_ptr && (uintptr_t)*array_ptr > 0x100000) {
                uint32_t len = *(uint32_t*)(*array_ptr + 0x18);
                uint8_t* data = (uint8_t*)(*array_ptr + 0x20);

                if (len > 0 && len < 4096) {
                    LOGI("================ [ 捕获明文封包 ] ================");
                    LOGI("长度: %u, 加密模式: %d", len, (int)a3);
                    
                    if (instance) {
                        uint8_t current_key = *(uint8_t*)((uintptr_t)instance + 16);
                        LOGI("当前滚动 Key: 0x%02X", current_key);
                    }
                    
                    LOGI("明文内容: %s", bytesToHex(data, len).c_str());
                    LOGI("=================================================");
                }
            }
        }
    }
    return old_PacketEncode(instance, packet, a3);
}

// --- 3. 核心：修改后的 hack_start ---
void hack_start(const char *game_data_dir) {
    LOGI(">>> 模块已进入游戏进程，等待系统稳定...");
    
    // 1. 先睡 15 秒，什么都不干，躲过 LIAPP 的启动即时扫描
    sleep(15); 

    bool load = false;
    for (int i = 0; i < 20; i++) {
        // 使用 xdl_open 只读模式尝试寻找
        void *handle = xdl_open("libil2cpp.so", XDL_DEFAULT);
        if (handle) {
            load = true;
            LOGI(">>> 发现 libil2cpp.so，准备环境...");

            // 2. 找到 so 后再初始化 Hook 引擎
            if (shadowhook_init(SHADOWHOOK_MODE_UNIQUE, false) != 0) {
                LOGE("ShadowHook 初始化失败");
                break;
            }

            xdl_info_t info;
            if (xdl_info(handle, XDL_DI_DLINFO, &info)) {
                void* target_addr = (void*)((uintptr_t)info.dli_fbase + 0x11B54C8);
                
                // 3. 执行 Hook
                shadowhook_hook_func_addr(target_addr, (void*)new_PacketEncode, (void**)&old_PacketEncode);
                
                if (old_PacketEncode != nullptr) {
                    LOGI(">>> 【核心】明文拦截器 Hook 成功！");
                }
            }

            // 4. (可选) 如果你不需要 Dump 符号表，可以注释掉下面两行，减少被检测风险
            // il2cpp_api_init(handle);
            // il2cpp_dump(game_data_dir);
            
            xdl_close(handle);
            break;
        } else {
            // 每 2 秒检查一次
            sleep(2);
        }
    }
}

// ... 后面所有的 GetLibDir 等辅助函数代码保持不变 ...
// [请保留你原本文件中的 GetLibDir 到 JNI_OnLoad 结尾的所有代码]

// --- 4. 保持你原有的 JNI 辅助函数不变 ---

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
    sleep(5);
    auto libart = dlopen("libart.so", RTLD_NOW);
    auto JNI_GetCreatedJavaVMs = (jint (*)(JavaVM **, jsize, jsize *)) dlsym(libart, "JNI_GetCreatedJavaVMs");
    JavaVM *vms_buf[1];
    JavaVM *vms;
    jsize num_vms;
    jint status = JNI_GetCreatedJavaVMs(vms_buf, 1, &num_vms);
    if (status == JNI_OK && num_vms > 0) {
        vms = vms_buf[0];
    } else {
        return false;
    }

    auto lib_dir = GetLibDir(vms);
    if (lib_dir.empty()) return false;
    if (lib_dir.find("/lib/x86") != std::string::npos) {
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
