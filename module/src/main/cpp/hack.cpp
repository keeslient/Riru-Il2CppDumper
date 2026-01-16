#include "hack.h"
#include "log.h"
#include "xdl.h"
#include "dobby.h" // 配合 FetchContent 自动下载的源码
#include <cstring>
#include <cstdio>
#include <unistd.h>
#include <dlfcn.h>
#include <jni.h>
#include <thread>
#include <sys/mman.h>
#include <android/log.h>
#include <fstream>
#include <cstdlib>
#include <vector>
#include <iomanip>
#include <sstream>

#define LOG_TAG "Perfare"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// =============================================================
// 工具函数：Hex 转 String
// =============================================================
std::string hexStr(unsigned char *data, int len) {
    std::stringstream ss;
    ss << std::hex;
    for (int i = 0; i < len; ++i)
        ss << std::setw(2) << std::setfill('0') << (int)data[i] << " ";
    return ss.str();
}

// =============================================================
// Dobby Hook 逻辑
// =============================================================

// 定义原始函数指针
void (*old_PacketEncode)(void* instance, void* packet, bool flag);

// 我们的新函数
void new_PacketEncode(void* instance, void* packet, bool flag) {
    
    // 只在 packet 有效时才干活
    if (packet != nullptr) {
        
        // 【防卡顿机制】每 20 次调用只打印 1 次 (防止刷屏卡死)
        // 如果发现漏包严重，可以把 20 改成 1，或者 5
        static int counter = 0;
        if (counter++ % 20 == 0) {
            
            // --- 仅在 64 位下执行解包逻辑 (防止 32 位编译报错) ---
            #if defined(__aarch64__)
            
                // 1. 获取 Packet 内部的 Buffer 指针 (根据你断点观测到的偏移 0x10)
                // C# 对象头通常是 16 字节，字段从 0x10 开始
                uintptr_t buffer_obj_addr = *(uintptr_t*)((uintptr_t)packet + 0x10);
                
                if (buffer_obj_addr != 0) {
                    // 2. 获取 Buffer 对象里的实际字节数组 (通常在 0x20)
                    // C# 数组结构: [Header] [Length] [Data]
                    // Data 开始的位置通常是 0x20
                    unsigned char* raw_data = (unsigned char*)(buffer_obj_addr + 0x20);
                    
                    // 3. 简单的内存有效性检查 (防止野指针崩溃)
                    // 如果地址太小(比如 0x0 - 0x10000)，说明肯定不是堆内存
                    if ((uintptr_t)raw_data > 0x100000) {
                        // 打印前 128 字节数据
                        LOGI(">>> [Dobby抓包] Data: %s", hexStr(raw_data, 128).c_str());
                    }
                }
                
            #endif
        }
    }

    // 【必须】调用原函数，否则游戏断网或逻辑中断
    if(old_PacketEncode) old_PacketEncode(instance, packet, flag);
}

// =============================================================
// 寻找基址逻辑 (90MB 策略)
// =============================================================
void* FindRealIl2CppBase() {
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return nullptr;
    char line[2048];
    void* best_addr = nullptr;
    unsigned long max_size = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "r-xp") && strstr(line, "/data/app") && strstr(line, ".so")) {
            if (strstr(line, "libunity.so") || strstr(line, "libmain.so") || strstr(line, "base.odex") || strstr(line, "webview")) continue;
            unsigned long start, end;
            if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
                unsigned long size = end - start;
                // 30MB 阈值
                if (size > 1024 * 1024 * 30) { 
                    if (size > max_size) {
                        max_size = size;
                        best_addr = (void*)start;
                    }
                }
            }
        }
    }
    fclose(fp);
    return best_addr;
}

// =============================================================
// 主线程逻辑
// =============================================================
void hack_start(const char *game_data_dir) {
    LOGI(">>> HACK START: Dobby 完美适配版 <<<");

    void* base_addr = nullptr;
    while (true) {
        base_addr = FindRealIl2CppBase();
        if (base_addr != nullptr) {
            LOGI("!!! 锁定真身 !!! Base Address: %p", base_addr);
            break;
        }
        sleep(1);
    }

    // 偏移量
    uintptr_t offset_PacketEncode = 0x11b54c8; 
    void* target_addr = (void*)((uintptr_t)base_addr + offset_PacketEncode);
    
    // --- 验证 OpCode (仅限 64 位) ---
    #if defined(__aarch64__)
        unsigned char* code = (unsigned char*)target_addr;
        // 打印前 4 字节，让你确认是不是 fb 6b bb a9
        LOGI("OpCode Check: %02x %02x %02x %02x", code[0], code[1], code[2], code[3]);
    #endif

    // --- 执行 Dobby Hook ---
    // DobbyHook 会自动处理内存属性修改、指令替换等复杂操作
    int ret = DobbyHook(target_addr, (void*)new_PacketEncode, (void**)&old_PacketEncode);
    
    if (ret == 0) {
        LOGI(">>> DobbyHook 成功！Hook 已激活！ <<<");
    } else {
        LOGI(">>> DobbyHook 失败: %d (请检查日志) <<<", ret);
    }

    // 保持线程存活
    while(true) sleep(10);
}

// =============================================================
// 模板导出代码 (勿动)
// =============================================================
std::string GetLibDir(JavaVM *vms) { return ""; }
static std::string GetNativeBridgeLibrary() { return ""; }
bool NativeBridgeLoad(const char *game_data_dir, int api_level, void *data, size_t length) { return false; }
void hack_prepare(const char *game_data_dir, void *data, size_t length) { hack_start(game_data_dir); }

#if defined(__arm__) || defined(__aarch64__)
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    auto game_data_dir = (const char *) reserved;
    std::thread hack_thread(hack_start, game_data_dir);
    hack_thread.detach();
    return JNI_VERSION_1_6;
}
#endif
