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
            // 顺便打印 ASCII 字符，方便你看明文
            text_out[i] = (buf[i] >= 32 && buf[i] <= 126) ? buf[i] : '.';
        }
        LOGI("[📦] %s (地址: %p)\nHEX : %s\nTEXT: %s", label, (void*)addr, hex_out, text_out);
    }
}

// --- 核心：明文包扫描雷达 ---
void scan_for_packet() {
    LOGI("[📡] 启动明文包雷达，寻找以 00 22 开头的内存...");
    
    // 我们只扫堆内存 (Heap)，因为发包 Buffer 都在堆里
    // 循环扫描，直到你杀掉游戏
    while (true) {
        FILE* fp = fopen("/proc/self/maps", "r");
        if (!fp) { sleep(1); continue; }
        
        char line[1024];
        while (fgets(line, sizeof(line), fp)) {
            // 目标：可读写的堆内存，通常包含 [anon:libc_malloc] 或 [heap]
            if (strstr(line, "rw-p") && 
               (strstr(line, "[anon:libc_malloc]") || strstr(line, "[heap]"))) {
                
                unsigned long tmp_start, tmp_end;
                if (sscanf(line, "%lx-%lx", &tmp_start, &tmp_end) == 2) {
                    uintptr_t start = (uintptr_t)tmp_start;
                    uintptr_t end = (uintptr_t)tmp_end;

                    // 优化：只扫前面的 2MB，通常 Buffer 不会太远
                    if (end - start > 2 * 1024 * 1024) end = start + 2 * 1024 * 1024;
                    
                    // 暴力扫描
                    // 你的包头是 00 22，也就是 short 34 (Big Endian)
                    // 在内存里可能是 00 22 (大端) 或者 22 00 (小端)
                    // 既然网络包通常是大端，我们搜 00 22
                    for (uintptr_t addr = start; addr < end - 34; addr += 4) {
                        unsigned char* p = (unsigned char*)addr;
                        
                        // 特征匹配：开头必须是 00 22 (长度34)
                        if (p[0] == 0x00 && p[1] == 0x22) {
                            
                            // 二次过滤：为了不被杂音干扰，我们要确保它不像已经加密的包
                            // 你抓的加密包第3字节是 CE/1D (大)
                            // 如果是明文，第3字节通常是命令字，或者是 00
                            // 我们把所有 00 22 开头的都打印出来让你认！
                            
                            // 打印出来给你看！
                            safe_hex_dump("发现疑似明文包", addr, 34);
                            
                            // 稍微停顿一下防止刷屏太快
                            usleep(1000); 
                        }
                    }
                }
            }
        }
        fclose(fp);
        LOGI("[💤] 一轮扫描结束，休眠 2 秒...");
        sleep(2);
    }
}

// --- 启动入口 ---
void hack_start(const char *game_data_dir) {
    LOGI("[🚀] 明文雷达启动...");
    
    // il2cpp dump (保留)
    void *handle = xdl_open("libil2cpp.so", 0);
    if (handle) {
        il2cpp_api_init(handle);
        il2cpp_dump(game_data_dir);
    }

    // 启动雷达
    std::thread(scan_for_packet).detach();
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
