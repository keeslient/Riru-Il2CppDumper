#include "hack.h"
#include "log.h"
#include "xdl.h"
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
#include <string>
#include <array>
#include <link.h>
#include <sys/system_properties.h>
#include <sys/syscall.h>
#include <linux/unistd.h>

#define LOG_TAG "Perfare"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// 辅助工具：Hex 转字符串
std::string hexStr(unsigned char *data, int len) {
    std::stringstream ss;
    ss << std::hex;
    for (int i = 0; i < len; ++i)
        ss << std::setw(2) << std::setfill('0') << (int)data[i] << " ";
    return ss.str();
}

// 核心逻辑：寻找真正的 il2cpp 基址 (体积策略)
void* FindRealIl2CppBase() {
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return nullptr;
    char line[2048];
    void* best_addr = nullptr;
    unsigned long max_size = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "r-xp")) {
            if (strstr(line, "/data/app") && strstr(line, ".so")) {
                if (strstr(line, "libunity.so") || strstr(line, "libmain.so") || 
                    strstr(line, "base.odex") || strstr(line, "webview")) continue;
                unsigned long start, end;
                if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
                    unsigned long size = end - start;
                    // 必须大于 30MB
                    if (size > 1024 * 1024 * 30) { 
                        if (size > max_size) {
                            max_size = size;
                            best_addr = (void*)start;
                            LOGI("发现大文件 (Size: %lu MB): %s", size / 1024 / 1024, line);
                        }
                    }
                }
            }
        }
    }
    fclose(fp);
    return best_addr;
}

void hack_start(const char *game_data_dir) {
    LOGI(">>> HACK START: 最终验证阶段 <<<");

    void* base_addr = nullptr;
    while (true) {
        base_addr = FindRealIl2CppBase();
        if (base_addr != nullptr) {
            LOGI("!!! 再次锁定真身 !!! Base Address: %p", base_addr);
            break;
        }
        sleep(1);
    }

    // 偏移量
    uintptr_t offset_PacketEncode = 0x11b54c8; 
    
    // 计算真实内存地址
    void* target_addr = (void*)((uintptr_t)base_addr + offset_PacketEncode);
    
    LOGI("-------------------------------------------------");
    LOGI("正在检查 PacketEncode 函数内容: %p", target_addr);
    
    // 【核心验证】直接读取该地址的指令码
    // 如果这里打印出非零数据（例如 FD 7B BF A9...），说明找对了！
    // 且 Dobby 之前之所以失败，是因为我们要么找错了地址，要么 LIAPP 保护了写权限
    
    unsigned char* code_ptr = (unsigned char*)target_addr;
    
    // 尝试读取前 16 个字节
    // 注意：这里没有 try-catch，如果地址非法可能会闪退，但 Maps 查出来的通常没事
    LOGI("OpCode [Header]: %s", hexStr(code_ptr, 16).c_str());
    LOGI("-------------------------------------------------");
    
    LOGI(">>> 如果上面显示了 OpCode，说明地址完全正确！<<<");
    LOGI(">>> 下一步就是解决 Dobby 编译报错并 Hook 它 <<<");

    while(true) sleep(10);
}

// -----------------------------------------------------------
// 保持原样以过编译
// -----------------------------------------------------------
std::string GetLibDir(JavaVM *vms) { return ""; } // 简化占位
static std::string GetNativeBridgeLibrary() { return ""; } // 简化占位
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
