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
#include <vector>

#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG "IMO_NINJA"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// --- 内存打印 ---
void safe_hex_dump(const char* label, uintptr_t addr, size_t len) {
#if defined(__aarch64__)
    if (addr < 0x10000000 || addr > 0x7fffffffff) return;
#else
    if (addr < 0x1000000) return;
#endif
    unsigned char buf[64];
    size_t copy_len = len > 64 ? 64 : len;
    
    if (memcpy(buf, (void*)addr, copy_len)) {
        char hex_out[256] = {0};
        char text_out[64] = {0};
        for(size_t i = 0; i < copy_len; i++) {
            sprintf(hex_out + strlen(hex_out), "%02X ", buf[i]);
            // 只显示可见字符，其他的显示点
            text_out[i] = (buf[i] >= 32 && buf[i] <= 126) ? buf[i] : '.';
        }
        // 打印发现的信息
        LOGI("\n========== [🔎 %s ] ==========\n地址: %p\nHEX : %s\nTEXT: %s\n==============================", 
             label, (void*)addr, hex_out, text_out);
    }
}

// --- 核心：Native 层精准扫描 ---
void scan_native_memory() {
    LOGI("[📡] 启动纯 Native 层扫描 (只看 SO 和 Native堆)...");
    
    while (true) {
        FILE* fp = fopen("/proc/self/maps", "r");
        if (!fp) { sleep(1); continue; }
        
        char line[1024];
        while (fgets(line, sizeof(line), fp)) {
            // 【1】黑名单：剔除 Java 层和系统层的所有干扰
            if (strstr(line, "/system/") || strstr(line, "/vendor/") || strstr(line, "/apex/") ||
                strstr(line, "dalvik") || strstr(line, "art") || 
                strstr(line, ".dex") || strstr(line, ".jar") || strstr(line, ".apk") || 
                strstr(line, "jit-cache")) {
                continue;
            }

            // 【2】白名单：只扫我们关心的区域
            bool is_target = false;
            
            // A. 游戏自带的 SO 库 (通常在 /data/app 下)
            if (strstr(line, "/data/app") && strstr(line, ".so")) {
                is_target = true;
            }
            // B. Native 堆内存 (malloc/new 分配出来的通常在这里)
            // [heap], [anon:libc_malloc], [anon:scudo] 等
            else if (strstr(line, "[heap]") || strstr(line, "[anon:libc_malloc]") || strstr(line, "[anon:scudo]")) {
                is_target = true;
            }
            // C. 有些加固会把内存标为普通的 [anon:...] 但没有名字
            // 如果它又是 rw-p 的，也有可能是缓冲区，暂时先放进来扫扫看
            else if (strstr(line, "rw-p") && strstr(line, "[anon:")) {
                is_target = true;
            }

            if (!is_target) continue;

            // 必须是可读写的
            if (strstr(line, "rw-p")) {
                unsigned long tmp_start, tmp_end;
                if (sscanf(line, "%lx-%lx", &tmp_start, &tmp_end) == 2) {
                    uintptr_t start = (uintptr_t)tmp_start;
                    uintptr_t end = (uintptr_t)tmp_end;

                    // 限制扫描大小，防止卡死，只扫前 2MB
                    if (end - start > 2 * 1024 * 1024) end = start + 2 * 1024 * 1024;

                    // 步长为 2
                    for (uintptr_t addr = start; addr < end - 34; addr += 2) {
                        unsigned char* p = (unsigned char*)addr;

                        // 目标长度: 34 (0x22)
                        
                        // 情况 1: 小端序 (22 00) -> 手机内存里最常见
                        if (p[0] == 0x22 && p[1] == 0x00) {
                            // 简单过滤：如果全是0肯定不是包
                            if (p[2] != 0x00 || p[3] != 0x00) {
                                safe_hex_dump("Native内存(小端)", addr, 34);
                            }
                        }
                        // 情况 2: 大端序 (00 22) -> 即将发送的网络流
                        else if (p[0] == 0x00 && p[1] == 0x22) {
                             if (p[2] != 0x00 || p[3] != 0x00) {
                                safe_hex_dump("Native内存(大端)", addr, 34);
                             }
                        }
                    }
                }
            }
        }
        fclose(fp);
        // 0.2秒扫一次，保持高频率
        usleep(200000); 
    }
}

// --- 启动入口 ---
void hack_start(const char *game_data_dir) {
    LOGI("[🚀] Native 猎杀者启动...");
    
    // il2cpp dump (保留)
    void *handle = xdl_open("libil2cpp.so", 0);
    if (handle) {
        il2cpp_api_init(handle);
        il2cpp_dump(game_data_dir);
    }

    // 启动 Native 扫描
    std::thread(scan_native_memory).detach();
}

// --- 接口 ---
void hack_prepare(const char *game_data_dir, void *data, size_t length) {
    std::string path = game_data_dir ? game_data_dir : "";
    std::thread([path]() {
        hack_start(path.c_str());
    }).detach();
}

#if defined(__arm__) || defined(__aarch64__)
extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    hack_prepare((const char*)reserved, nullptr, 0);
    return JNI_VERSION_1_6;
}
#endif
