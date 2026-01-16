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
#include <signal.h>
#include <ucontext.h>

#define LOG_TAG "Perfare"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// =============================================================
// 全局变量
// =============================================================
uintptr_t g_target_addr = 0;
uint32_t g_backup_instruction = 0; // 用来存原始指令 (fb 6b bb a9)
bool g_trap_triggered = false;

// Hex 转字符串工具
std::string hexStr(unsigned char *data, int len) {
    std::stringstream ss;
    ss << std::hex;
    for (int i = 0; i < len; ++i)
        ss << std::setw(2) << std::setfill('0') << (int)data[i] << " ";
    return ss.str();
}

// =============================================================
// 信号处理 (核心逻辑)
// =============================================================
void TrapHandler(int signum, siginfo_t *info, void *context) {
    #if defined(__aarch64__)
    ucontext_t *uc = (ucontext_t *)context;
    uintptr_t pc = uc->uc_mcontext.pc;
    uintptr_t x1_packet = uc->uc_mcontext.regs[1]; // x1 = SendingPacket 对象

    if (pc == g_target_addr) {
        LOGI(">>> [软件断点命中] 抓到 Packet 对象! <<<");
        
        if (x1_packet != 0) {
            // 1. 打印 Packet 对象本身 (盒子)
            // LOGI("Packet Obj: %p", (void*)x1_packet);

            // 2. 【核心修改】尝试读取里面的 Buffer
            // 在 64位 Unity 中，第一个字段通常在偏移 0x10
            uintptr_t field_1_ptr = *(uintptr_t*)(x1_packet + 0x10);
            
            if (field_1_ptr != 0) {
                LOGI(">>> 发现内部 Buffer 指针: %p <<<", (void*)field_1_ptr);
                
                // 3. 读取 Buffer 的内容
                // C# 数组结构: [Header 0x00-0x10] [Length 0x18] [Data 0x20...]
                // 我们直接读偏移 0x20 处的数据，这就是真正的明文封包！
                
                unsigned char* data_ptr = (unsigned char*)(field_1_ptr + 0x20);
                
                // 为了防止野指针崩溃，简单检查一下地址合法性(简略版)
                // 这里直接打印，如果闪退说明偏移不对，但这通常是通用的
                LOGI("=== 真实封包内容 (Hex) ===");
                LOGI("%s", hexStr(data_ptr, 128).c_str()); 
                LOGI("==========================");
            } else {
                LOGI("Buffer 指针为空，可能偏移量不是 0x10");
            }
        }

        // --- 下面是还原逻辑，保持不变 ---
        void *page_start = (void *)(g_target_addr & ~(getpagesize() - 1));
        mprotect(page_start, getpagesize(), PROT_READ | PROT_WRITE | PROT_EXEC);
        *(uint32_t*)g_target_addr = g_backup_instruction;
        __builtin___clear_cache((char*)g_target_addr, (char*)g_target_addr + 4);
        g_trap_triggered = true;
        LOGI(">>> 指令已还原，游戏继续 <<<");
    }
    #endif
}

// =============================================================
// 安装软件断点 (写入 BRK)
// =============================================================
void InstallSoftwareBreakpoint(uintptr_t addr) {
    if (g_trap_triggered) return;

    // 1. 计算内存页对齐地址
    void *page_start = (void *)(addr & ~(getpagesize() - 1));
    
    // 2. 强行提权：让这块内存可写
    if (mprotect(page_start, getpagesize(), PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
        LOGI("mprotect 失败，无法修改内存权限! (Errno: %d)", errno);
        return;
    }

    // 3. 备份原始指令 (应该是 fb 6b bb a9)
    g_backup_instruction = *(uint32_t*)addr;
    LOGI("备份原始指令: %08x", g_backup_instruction);

    // 4. 写入自爆指令 BRK #0 (Hex: D4200000 - AArch64专用)
    #if defined(__aarch64__)
    *(uint32_t*)addr = 0xD4200000;
    #endif
    
    // 5. 刷新缓存
    __builtin___clear_cache((char*)addr, (char*)addr + 4);

    // 6. 注册信号接收器
    struct sigaction sa;
    memset(&sa, 0, sizeof(struct sigaction));
    sa.sa_sigaction = TrapHandler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGTRAP, &sa, NULL); // 监听 SIGTRAP 信号

    LOGI(">>> 软件断点已写入: %p (BRK 指令) <<<", (void*)addr);
}

// =============================================================
// 寻找基址逻辑 (90MB 大文件策略)
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
// 主逻辑
// =============================================================
void hack_start(const char *game_data_dir) {
    LOGI(">>> HACK START: 终极软件断点模式 (无需 Root 权限) <<<");

    void* base_addr = nullptr;
    while (true) {
        base_addr = FindRealIl2CppBase();
        if (base_addr != nullptr) {
            LOGI("!!! 锁定真身 !!! Base Address: %p", base_addr);
            break;
        }
        sleep(1);
    }

    // 计算地址
    uintptr_t offset_PacketEncode = 0x11b54c8; 
    g_target_addr = (uintptr_t)base_addr + offset_PacketEncode;
    LOGI(">>> 目标地址: %p <<<", (void*)g_target_addr);

    // 验证
    unsigned char* code = (unsigned char*)g_target_addr;
    LOGI("OpCode Check: %02x %02x %02x %02x", code[0], code[1], code[2], code[3]);

    // 安装断点
    InstallSoftwareBreakpoint(g_target_addr);

    while(true) sleep(10);
}

// 模板代码
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
