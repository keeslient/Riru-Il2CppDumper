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

// --- 内存打印 (带 ASCII 对照) ---
void safe_hex_dump(const char* label, uintptr_t addr, size_t len) {
#if defined(__aarch64__)
    if (addr < 0x10000000 || addr > 0x7fffffffff) return;
#else
    if (addr < 0x1000000) return;
#endif
    unsigned char buf[64];
    size_t copy_len = len > 64 ? 64 : len;
    
    // 尝试读取
    if (memcpy(buf, (void*)addr, copy_len)) {
        char hex_out[256] = {0};
        char text_out[64] = {0};
        for(size_t i = 0; i < copy_len; i++) {
            sprintf(hex_out + strlen(hex_out), "%02X ", buf[i]);
            // 过滤非打印字符，方便看明文
            text_out[i] = (buf[i] >= 32 && buf[i] <= 126) ? buf[i] : '.';
        }
        LOGI("\n========== [🔎 %s ] ==========\n地址: %p\nHEX : %s\nTEXT: %s\n==============================", 
             label, (void*)addr, hex_out, text_out);
    }
}

// --- 核心：极速双向雷达 ---
void scan_for_packet_fast() {
    LOGI("[📡] 极速雷达启动：同时搜索 00 22 (大端) 和 22 00 (小端)...");
    
    while (true) {
        FILE* fp = fopen("/proc/self/maps", "r");
        if (!fp) { usleep(100000); continue; } // 100ms 重试
        
        char line[1024];
        while (fgets(line, sizeof(line), fp)) {
            // 重点关注：栈 (stack) 和 匿名堆 (libc_malloc)
            // 因为临时组包通常在栈上，或者很小的堆内存里
            if (strstr(line, "rw-p") && 
               (strstr(line, "[stack]") || strstr(line, "[anon:libc_malloc]"))) {
                
                unsigned long tmp_start, tmp_end;
                if (sscanf(line, "%lx-%lx", &tmp_start, &tmp_end) == 2) {
                    uintptr_t start = (uintptr_t)tmp_start;
                    uintptr_t end = (uintptr_t)tmp_end;

                    // 优化：只扫前 512KB，提高速度，防止漏掉瞬时包
                    if (end - start > 512 * 1024) end = start + 512 * 1024;

                    for (uintptr_t addr = start; addr < end - 34; addr += 2) { // 步长改为2，防止错位
                        unsigned char* p = (unsigned char*)addr;
                        
                        // 【修正点 1】匹配小端序 (22 00) -> 手机内存常用
                        bool match_le = (p[0] == 0x22 && p[1] == 0x00);
                        
                        // 【修正点 2】匹配大端序 (00 22) -> 网络流常用
                        bool match_be = (p[0] == 0x00 && p[1] == 0x22);

                        if (match_le || match_be) {
                            // 二次检查：你的加密包第3字节是 CE，如果是明文，这里绝不应该是 CE
                            // 我们可以加一个简单的过滤器，比如第3字节必须是 00~0F (常见命令字)
                            // 或者不做过滤，全部打印出来人工看
                            
                            safe_hex_dump(match_le ? "疑似明文(小端)" : "疑似明文(大端)", addr, 34);
                            
                            // 稍微停顿，避免单次扫描卡死，但要快
                            // usleep(10); 
                        }
                    }
                }
            }
        }
        fclose(fp);
        
        // 【修正点 3】极大缩短休眠时间，从 2秒 改为 0.2秒
        // 必须快，才能抓住那 0.01 秒的瞬间
        usleep(200000); 
    }
}

// --- 启动入口 ---
void hack_start(const char *game_data_dir) {
    LOGI("[🚀] 猎杀者启动...");
    
    // il2cpp dump (保留)
    void *handle = xdl_open("libil2cpp.so", 0);
    if (handle) {
        il2cpp_api_init(handle);
        il2cpp_dump(game_data_dir);
    }

    // 启动极速雷达
    std::thread(scan_for_packet_fast).detach();
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
