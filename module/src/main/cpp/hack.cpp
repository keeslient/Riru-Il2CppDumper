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
    LOGI("[📡] 暴力嗅探雷达已启动，开始全内存搜索 Wireshark 特征包...");

    // 获取目标库基址
    uintptr_t base = 0;
    while (base == 0) {
        base = get_module_base("libfvctyud.so");
        sleep(1);
    }

    // 重点：我们不再等它触发，我们主动监控 libfvctyud.so 的数据段
    // 假设它的数据段在基址往后 0x100000 左右
    uintptr_t data_section = base + 0x100000; 

    while (true) {
        // 扫描内存中是否出现了 Wireshark 抓到的特征头：08 00 00 00
        for (uintptr_t addr = data_section; addr < data_section + 0x50000; addr += 8) {
            unsigned char* p = (unsigned char*)addr;
            if (p[0] == 0x08 && p[1] == 0x00 && p[2] == 0x00 && p[3] == 0x00) {
                LOGI("[🔥] 雷达发现疑似明文包！地址: %p", (void*)addr);
                safe_hex_dump("捕获内容", addr, 64);
                // 抓到后停一下，防止日志刷屏
                sleep(2);
            }
        }
        usleep(500000); // 每 0.5 秒扫一次
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
