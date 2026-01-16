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
#include <cstdlib>
#include <vector>
#include <iomanip>
#include <sstream>
#include <signal.h>
#include <ucontext.h>

#define LOG_TAG "Perfare"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// =============================================================
// 全局状态
// =============================================================
uintptr_t g_target_addr = 0;
uint32_t g_backup_instruction = 0;
// 标记当前断点是否处于激活状态
volatile bool g_breakpoint_active = false; 

// Hex 转 String
std::string hexStr(unsigned char *data, int len) {
    std::stringstream ss;
    ss << std::hex;
    for (int i = 0; i < len; ++i)
        ss << std::setw(2) << std::setfill('0') << (int)data[i] << " ";
    return ss.str();
}

// =============================================================
// 信号处理器 (抓包逻辑)
// =============================================================
void TrapHandler(int signum, siginfo_t *info, void *context) {
    #if defined(__aarch64__)
    ucontext_t *uc = (ucontext_t *)context;
    uintptr_t pc = uc->uc_mcontext.pc;
    uintptr_t x1_packet = uc->uc_mcontext.regs[1]; // x1 = Packet对象

    // 只有在断点激活且地址匹配时才处理
    if (pc == g_target_addr && g_breakpoint_active) {
        
        // --- 抓包逻辑 ---
        if (x1_packet != 0) {
            // 读取 Packet -> Buffer (0x10) -> Data (0x20)
            // 注意：这里要做指针检查，防止崩溃
            uintptr_t buffer_obj = 0;
            // 简单防崩：检查指针是否在用户空间合理范围
            if (x1_packet > 0x100000) {
                 buffer_obj = *(uintptr_t*)(x1_packet + 0x10);
            }
            
            if (buffer_obj > 0x100000) {
                unsigned char* raw_data = (unsigned char*)(buffer_obj + 0x20);
                // 打印前 64 字节
                LOGI(">>> [采样抓包] Data: %s", hexStr(raw_data, 64).c_str());
            } else {
                // 如果解包失败，至少打印个对象地址证明抓到了
                LOGI(">>> [采样抓包] 捕获对象: %p (Buffer为空)", (void*)x1_packet);
            }
        }

        // --- 还原代码 (放行游戏) ---
        // 1. 修改权限
        void *page_start = (void *)(g_target_addr & ~(getpagesize() - 1));
        mprotect(page_start, getpagesize(), PROT_READ | PROT_WRITE | PROT_EXEC);
        
        // 2. 写回原始指令
        *(uint32_t*)g_target_addr = g_backup_instruction;
        
        // 3. 刷新缓存
        __builtin___clear_cache((char*)g_target_addr, (char*)g_target_addr + 4);
        
        // 4. 标记断点已失效
        g_breakpoint_active = false;
        
        // LOGI(">>> 拦截结束，游戏恢复流畅运行 <<<");
    }
    #endif
}

// =============================================================
// 安装断点
// =============================================================
void InstallTrap() {
    if (g_target_addr == 0) return;
    
    // 如果已经在激活状态，就别重复写了
    if (g_breakpoint_active) return;

    void *page_start = (void *)(g_target_addr & ~(getpagesize() - 1));
    if (mprotect(page_start, getpagesize(), PROT_READ | PROT_WRITE | PROT_EXEC) == 0) {
        
        // 第一次安装时备份指令
        if (g_backup_instruction == 0) {
             g_backup_instruction = *(uint32_t*)g_target_addr;
             LOGI("备份原始指令: %08x", g_backup_instruction);
        }

        // 写入 BRK 指令 (AArch64)
        #if defined(__aarch64__)
        *(uint32_t*)g_target_addr = 0xD4200000;
        #endif

        __builtin___clear_cache((char*)g_target_addr, (char*)g_target_addr + 4);
        
        g_breakpoint_active = true;
        // LOGI(">>> 陷阱已布设，等待猎物... <<<");
    }
}

// =============================================================
// 寻找基址
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
    LOGI(">>> HACK START: 纯代码采样模式 (无任何依赖) <<<");

    // 1. 注册信号处理 (一次即可)
    struct sigaction sa;
    memset(&sa, 0, sizeof(struct sigaction));
    sa.sa_sigaction = TrapHandler;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER; 
    sigaction(SIGTRAP, &sa, NULL);

    // 2. 找地址
    void* base_addr = nullptr;
    while (base_addr == nullptr) {
        base_addr = FindRealIl2CppBase();
        sleep(1);
    }
    
    // 你的偏移
    g_target_addr = (uintptr_t)base_addr + 0x11b54c8;
    LOGI(">>> 目标锁定: %p <<<", (void*)g_target_addr);

    // 3. 循环采样 (核心机制)
    while (true) {
        // 尝试下断点
        InstallTrap();
        
        // 休息 2 秒
        // 在这 2 秒内：
        // A. 如果游戏没发包 -> 断点一直留着，等待下一秒
        // B. 如果游戏发包了 -> 触发中断 -> 打印数据 -> 断点消失 -> 游戏流畅运行
        sleep(2); 
    }
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
