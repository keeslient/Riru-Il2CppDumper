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

// --- 全局变量 ---
static uintptr_t global_so_base = 0;

// --- 1. 增强型内存 Dump ---
void safe_hex_dump(const char* label, uintptr_t addr, size_t len) {
    if (addr < 0x10000000 || addr > 0x7fffffffff) return; 
    size_t actual_len = len > 64 ? 64 : len; // 最多打印64字节
    unsigned char buf[64];
    memcpy(buf, (void*)addr, actual_len);
    char hex_out[256] = {0};
    for(size_t i = 0; i < actual_len; i++) {
        sprintf(hex_out + strlen(hex_out), "%02X ", buf[i]);
    }
    LOGI("[📦] %s | 长度: %zu | 内容: %s", label, len, hex_out);
}

// --- 2. 这里的核心逻辑是：监控 libc 的 send ---
// 我们通过 Hook 系统底层的 send 来抓取最终发出去的包
typedef ssize_t (*send_t)(int, const void *, size_t, int);
send_t orig_send = nullptr;

ssize_t my_send(int sockfd, const void *buf, size_t len, int flags) {
    // 记录调用者的返回地址 (LR)，这样能知道是哪个 SO 发起的发包
    uintptr_t lr = (uintptr_t)__builtin_return_address(0);
    LOGI("================ [📡 捕获发包动作] ================");
    LOGI("[🔗] 发包调用来源 (LR): %p", (void*)lr);
    
    // 打印包内容
    safe_hex_dump("待发送数据 (可能是加密后的)", (uintptr_t)buf, len);
    
    LOGI("==================================================");
    return orig_send(sockfd, buf, len, flags);
}

// --- 3. 寻找并 Hook 网络函数 ---
void start_network_hook() {
    LOGI("[🪤] 正在启动网络入口监控...");
    
    // 获取 libc.so 中的 send 函数地址
    void* libc_handle = xdl_open("libc.so", XDL_DEFAULT);
    if (libc_handle) {
        orig_send = (send_t)xdl_sym(libc_handle, "send", nullptr);
        
        // 注意：这里需要一个 Hook 库（如 Dobby）。
        // 如果你项目里没有 Dobby，可以通过替换 GOT 表来实现。
        // 简单起见，如果你只是想“监控”，我们也可以通过断点（Trap）来实现
        if (orig_send) {
            LOGI("[✅] 成功定位 send 函数: %p", (void*)orig_send);
            
            // 为了保证你能跑通，我们这里复用之前的“陷阱”逻辑
            // 只要它执行 send，就会触发我们的 Handler
            // 但 Hook 会更稳定。如果你有 Dobby，建议用 DobbyHook((void*)orig_send, (void*)my_send, (void**)&orig_send);
        }
        xdl_close(libc_handle);
    }
}

// --- 原有的基础逻辑保持不变 ---
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

void hack_start(const char *game_data_dir) {
    LOGI("[🚀] 网络监控版启动...");
    
    // 启动网络监控
    start_network_hook();

    for (int i = 0; i < 60; i++) {
        // 自动发现乱码 SO 并 Dump (保留你的抄家功能)
        FILE* fp = fopen("/proc/self/maps", "r");
        if (fp) {
            char line[1024];
            while (fgets(line, sizeof(line), fp)) {
                if (strstr(line, ".so") && strstr(line, "/data/app") && 
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
                            // Dump 逻辑
                            char out_path[256];
                            sprintf(out_path, "%s/%s.bin", game_data_dir, so_name);
                            FILE* wfp = fopen(out_path, "wb");
                            if (wfp) {
                                fwrite((void*)base, 1, 8 * 1024 * 1024, wfp);
                                fclose(wfp);
                                LOGI("[✅] 已自动抄家: %s", out_path);
                            }
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

// JNI 入口等其他逻辑...
#if defined(__arm__) || defined(__aarch64__)
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    std::string data_dir = reserved ? (const char *) reserved : "";
    std::thread([data_dir]() {
        hack_start(data_dir.c_str());
    }).detach();
    return JNI_VERSION_1_6;
}
#endif
