#include "hack.h"
#include "log.h"
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
// 全局变量
// =============================================================
uintptr_t g_target_addr = 0;
uint32_t g_backup_instruction = 0; // 备份原始指令
bool g_is_hooked = false;

// Hex 转字符串
std::string hexStr(unsigned char *data, int len) {
    std::stringstream ss;
    ss << std::hex;
    for (int i = 0; i < len; ++i)
        ss << std::setw(2) << std::setfill('0') << (int)data[i] << " ";
    return ss.str();
}

// =============================================================
// 信号处理 (捕获 SIGTRAP)
// =============================================================
void TrapHandler(int signum, siginfo_t *info, void *context) {
    ucontext_t *uc = (ucontext_t *)context;
    
    // 获取 PC 指针
    #if defined(__aarch64__)
    uintptr_t pc = uc->uc_mcontext.pc;
    uintptr_t arg1_packet = uc->uc_mcontext.regs[1]; // x1 = packet
    #else
    return; // 不支持 32 位
    #endif

    // 也就是我们下断点的地方
    if (pc == g_target_addr) {
        LOGI(">>> [软件断点命中] 成功拦截! <<<");
        
        if (arg1_packet != 0) {
            // 打印数据!
            LOGI("Packet Addr: %p", (void*)arg1_packet);
            LOGI("Data: %s", hexStr((unsigned char*)arg1_packet, 128).c_str());
        } else {
            LOGI("Packet Addr is NULL");
        }

        // =================================================
        // 关键步骤：还原代码，让游戏继续运行
        // =================================================
        
        // 1. 修改内存权限为可写
        void *page_start = (void *)(g_target_addr & ~(getpagesize() - 1));
        mprotect(page_start, getpagesize(), PROT_READ | PROT_WRITE | PROT_EXEC);

        // 2. 还原原始指令 (把 BRK 改回原来的指令)
        *(uint32_t*)g_target_addr = g_backup_instruction;

        // 3. 刷新指令缓存 (必须做，否则 CPU 可能还记得旧指令)
        __builtin___clear_cache((char*)g_target_addr, (char*)g_target_addr + 4);

        LOGI(">>> 指令已还原，放行游戏 (One-Shot Hook) <<<");
        
        // 注意：这种简易写法只能抓到“第一次”发包。
        // 因为指令还原后，断点就没了。
        // 如果想一直抓，需要“单步调试”机制，代码量太大，先确保能抓到这一条！
    }
}

// =============================================================
// 安装软件断点
// =============================================================
void InstallSoftwareBreakpoint(uintptr_t addr) {
    if (g_is_hooked) return;

    // 1. 计算页对齐地址
    void *page_start = (void *)(addr & ~(getpagesize() - 1));
    
    // 2. 修改权限：允许读、写、执行
    if (mprotect(page_start, getpagesize(), PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
        LOGI("mprotect 失败，无法修改内存权限!");
        return;
    }

    // 3. 备份原始指令
    g_backup_instruction = *(uint32_t*)addr;
    LOGI("备份原始指令: %08x", g_backup_instruction);

    // 4. 写入 BRK #0 指令 (Hex: D4200000)
    // 当 CPU 执行到这条指令时，会抛出 SIGTRAP 信号
    *(uint32_t*)addr = 0xD4200000;
    
    // 5. 刷新缓存
    __builtin___clear_cache((char*)addr, (char*)addr + 4);

    // 6. 注册信号处理函数
    struct sigaction sa;
    memset(&sa, 0, sizeof(struct sigaction));
    sa.sa_sigaction = TrapHandler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGTRAP, &sa, NULL);

    g_is_hooked = true;
    LOGI(">>> 软件断点已写入: %p (BRK 指令) <<<", (void*)addr);
}

// =============================================================
// 寻找基址逻辑 (保持不变)
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
    LOGI(">>> HACK START: 软件断点模式 (无需系统权限) <<<");

    void* base_addr = nullptr;
    while (true) {
        base_addr = FindRealIl2CppBase();
        if (base_addr != nullptr) {
            LOGI("!!! 锁定真身 !!! Base Address: %p", base_addr);
            break;
        }
        sleep(1);
    }

    uintptr_t offset_PacketEncode = 0x11b54c8; 
    g_target_addr = (uintptr_t)base_addr + offset_PacketEncode;
    LOGI(">>> 目标地址: %p <<<", (void*)g_target_addr);

    // 验证 OpCode
    unsigned char* code = (unsigned char*)g_target_addr;
    LOGI("OpCode Check: %02x %02x %02x %02x", code[0], code[1], code[2], code[3]);

    // 安装断点
    InstallSoftwareBreakpoint(g_target_addr);

    while(true) sleep(10);
}

// 模板代码 (保持不变)
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
