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

// --- 智能打印 (只打印像封包的数据) ---
void safe_hex_dump_smart(uintptr_t addr) {
#if defined(__aarch64__)
    if (addr < 0x10000000 || addr > 0x7fffffffff) return;
#endif
    unsigned char buf[64];
    // 读取 34 字节 (封包长度)
    if (memcpy(buf, (void*)addr, 34)) {
        
        // ============= 强力过滤区 =============
        
        // 1. 排除 JSON 字符串 (UTF-16LE 的 " 是 22 00)
        // 既然我们只扫 00 22 (大端)，这个其实已经排除大部分了
        
        // 2. 排除 指针数组
        // 如果数据长这样: 00 22 XX XX 70 00 00 B4 ... 这通常是虚函数表或者对象指针
        // 检查第 5-8 字节，如果是高位地址特征 (比如 > 0x60)，大概率是指针
        if (buf[7] > 0x60 || buf[5] > 0x60) return;

        // 3. 排除全零填充
        // 如果 00 22 后面全是 00，大概率是无意义内存
        if (buf[2] == 0 && buf[3] == 0 && buf[4] == 0) return;

        // 4. 排除 HTTP 文本 (以 00 22 开头的情况比较少，但防万一)
        if (buf[2] >= 0x20 && buf[2] <= 0x7E && buf[3] >= 0x20 && buf[3] <= 0x7E) {
             // 如果看起来像纯文本，也可能是误报，但先不过滤，手动看
        }

        // ======================================

        char hex_out[256] = {0};
        char text_out[64] = {0};
        for(size_t i = 0; i < 34; i++) {
            sprintf(hex_out + strlen(hex_out), "%02X ", buf[i]);
            text_out[i] = (buf[i] >= 32 && buf[i] <= 126) ? buf[i] : '.';
        }
        
        // 重点标注：如果跟 WPE 包头 (CE / 1D) 相似
        // 你之前的包：00 22 CE ... 和 00 22 1D ...
        const char* tag = "[❓ 疑似目标]";
        if (buf[2] == 0xCE || buf[2] == 0x1D) {
            tag = "[🔥 极度疑似 (匹配WPE头)]";
        }

        LOGI("\n%s\n地址: %p\nHEX : %s\nTEXT: %s\n--------------------------------", 
             tag, (void*)addr, hex_out, text_out);
    }
}

// --- 核心：只扫 Native 堆 + 大端序 00 22 ---
void scan_native_heap_only() {
    LOGI("[📡] 启动精准过滤扫描 (只找 00 22 开头的非指针数据)...");
    
    while (true) {
        FILE* fp = fopen("/proc/self/maps", "r");
        if (!fp) { sleep(1); continue; }
        
        char line[1024];
        while (fgets(line, sizeof(line), fp)) {
            // 只关注 匿名堆内存 和 游戏SO
            // 排除掉 system, fonts, jar, apk, dex, art
            if (strstr(line, "/system/") || strstr(line, ".dex") || strstr(line, ".art") ||
                strstr(line, ".apk") || strstr(line, ".jar") || strstr(line, "/fonts/")) {
                continue;
            }

            bool is_target = false;
            if (strstr(line, "[anon:libc_malloc]") || strstr(line, "[heap]")) is_target = true;
            else if (strstr(line, "/data/app") && strstr(line, ".so")) is_target = true;
            
            if (!is_target) continue;

            if (strstr(line, "rw-p")) {
                unsigned long tmp_start, tmp_end;
                if (sscanf(line, "%lx-%lx", &tmp_start, &tmp_end) == 2) {
                    uintptr_t start = (uintptr_t)tmp_start;
                    uintptr_t end = (uintptr_t)tmp_end;

                    // 限制扫描范围，防止卡顿
                    if (end - start > 4 * 1024 * 1024) end = start + 4 * 1024 * 1024;

                    // 步长为 2
                    for (uintptr_t addr = start; addr < end - 34; addr += 2) {
                        unsigned char* p = (unsigned char*)addr;

                        // 【核心修改】只找 大端序 (00 22)
                        // 因为 WPE 抓到的是 00 22，说明发包函数组装完的数据就是这个顺序
                        if (p[0] == 0x00 && p[1] == 0x22) {
                            // 交给智能打印函数去鉴别
                            safe_hex_dump_smart(addr);
                        }
                    }
                }
            }
        }
        fclose(fp);
        usleep(200000); // 200ms
    }
}

// --- 启动入口 ---
void hack_start(const char *game_data_dir) {
    LOGI("[🚀] 去噪雷达启动...");
    
    // il2cpp dump (保留)
    void *handle = xdl_open("libil2cpp.so", 0);
    if (handle) {
        il2cpp_api_init(handle);
        il2cpp_dump(game_data_dir);
    }

    std::thread(scan_native_heap_only).detach();
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
