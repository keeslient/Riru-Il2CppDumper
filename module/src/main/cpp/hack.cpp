#include <jni.h>
#include <android/log.h>
#include <dlfcn.h>
#include <unistd.h>
#include <string>
#include <cstring>
#include <thread>
#include <sstream>
#include <iomanip>
#include <sys/mman.h>
#include "xdl.h"

// --- 日志宏定义：adb logcat -s Perfare_Packet:V *:S ---
#define LOG_TAG "Perfare_Packet"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// --- 十六进制转换工具 ---
std::string HexDump(unsigned char* buf, int len) {
    std::stringstream ss;
    for (int i = 0; i < (len > 128 ? 128 : len); ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)buf[i] << " ";
    }
    return ss.str();
}

// --- 异步工作线程 ---
void hack_thread() {
    LOGI("异步工作线程启动，正在静候 libil2cpp.so 加载...");
    
    void *handle = nullptr;
    // 循环查找 libil2cpp.so，直到它被载入内存
    while (!handle) {
        handle = xdl_open("libil2cpp.so", XDL_DEFAULT);
        if (!handle) {
            usleep(500000); // 每0.5秒查一次
        }
    }

    LOGI("成功抓到 libil2cpp.so！地址: %p，等待游戏初始化 (10s)...", handle);
    sleep(10); 

    // 这里通过 xdl 寻找 PacketEncode 的偏移或符号
    // 如果符号被抹除，你可以直接使用 (size_t)handle + 0xYOUR_OFFSET
    void* target_func = xdl_sym(handle, "PacketEncode", nullptr);
    
    if (target_func) {
        LOGI("已定位 PacketEncode 函数: %p", target_func);
        /**
         * 由于我们不用 Hook 库，这里你可以直接在这个地址通过读内存看数据。
         * 如果你一定要拦截，可以在这里配合内存断点或使用最原始的指令覆盖。
         * 为了稳定性，我们先在这里打印该函数头部的指令，确认位置。
         **/
        unsigned char* data = (unsigned char*)target_func;
        LOGI("函数前16字节内容: %s", HexDump(data, 16).c_str());
    } else {
        LOGE("未能在符号表中找到 PacketEncode，请检查函数名或改用偏移地址。");
    }

    xdl_close(handle);
}

// Zygisk 入口
void hack_start(const char *game_data_dir) {
    // 开启异步线程，避免主线程卡死
    std::thread t(hack_thread);
    t.detach();
}

extern "C" {
    void riru_init(void *arg) {}
}
