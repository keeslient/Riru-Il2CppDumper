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
#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG "IMO_NINJA"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// --- 1. 内存嗅探函数 ---
void safe_hex_dump(const char* label, uintptr_t addr, size_t len) {
    if (addr < 0x10000000 || addr > 0x7fffffffff) return; 
    size_t actual_len = len > 64 ? 64 : len;
    unsigned char buf[64];
    // 简单尝试读取，如果崩溃说明地址不可读
    if (memcpy(buf, (void*)addr, actual_len)) {
        char hex_out[256] = {0};
        for(size_t i = 0; i < actual_len; i++) {
            sprintf(hex_out + strlen(hex_out), "%02X ", buf[i]);
        }
        LOGI("[📦] %s | 长度: %zu | 内容: %s", label, len, hex_out);
    }
}

// --- 2. 网络拦截逻辑 ---
// 注意：由于没有 Hook 库，我们暂时通过打印日志来记录，
// 核心逻辑在 hack_start 的 LR 追踪。
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

// --- 3. 核心启动函数 ---
void hack_start(const char *game_data_dir) {
    LOGI("[🚀] 网络监控嗅探模式启动...");
    
    bool trap_done = false;
    for (int i = 0; i < 60; i++) {
        FILE* fp = fopen("/proc/self/maps", "r");
        if (fp) {
            char line[1024];
            while (fgets(line, sizeof(line), fp)) {
                // 搜索核心乱码库
                if (!trap_done && strstr(line, ".so") && strstr(line, "/data/app") && 
                    !strstr(line, "libmain.so") && !strstr(line, "libunity.so") && 
                    !strstr(line, "libil2cpp.so")) {
                    
                    char* so_path = strchr(line, '/');
                    char* so_name = strrchr(so_path, '/');
                    if (so_name) {
                        so_name++;
                        so_name[strcspn(so_name, "\n")] = 0;
                        
                        uintptr_t base = get_module_base(so_name);
                        if (base) {
                            LOGI("[📡] 发现核心库: %s 基址: %p", so_name, (void*)base);
                            // 自动抄家镜像
                            char out_path[256];
                            sprintf(out_path, "%s/%s_dump.bin", game_data_dir, so_name);
                            FILE* wfp = fopen(out_path, "wb");
                            if (wfp) {
                                fwrite((void*)base, 1, 8 * 1024 * 1024, wfp);
                                fclose(wfp);
                                LOGI("[✅] 自动抄家成功: %s", out_path);
                            }
                            trap_done = true;
                        }
                    }
                }
            }
            fclose(fp);
        }

        void *handle = xdl_open("libil2cpp.so", 0);
        if (handle) {
            il2cpp_api_init(handle);
            il2cpp_dump(game_data_dir);
            break;
        }
        ::sleep(2);
    }
}

// --- 4. Zygisk 调用的关键出口函数 ---
// 修正：必须使用 extern "C" 或者确保与 hack.h 声明一致
void hack_prepare(const char *game_data_dir, void *data, size_t length) {
    LOGI("[🔗] Zygisk 准备调用 hack_start...");
    // 这里的 data 和 length 是原本 NativeBridge 使用的，在常规模式下可以忽略
    std::string path = game_data_dir ? game_data_dir : "";
    std::thread([path]() {
        hack_start(path.c_str());
    }).detach();
}

// --- 5. 兼容普通 JNI 加载入口 ---
#if defined(__arm__) || defined(__aarch64__)
extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    const char* path = (const char*)reserved;
    hack_prepare(path, nullptr, 0);
    return JNI_VERSION_1_6;
}
#endif
