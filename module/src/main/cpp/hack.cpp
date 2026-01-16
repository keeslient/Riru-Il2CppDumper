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
#include <fstream>
#include <cstdlib>
#include <vector>
#include <iomanip>
#include <sstream>
#include <string>
#include <array>
#include <link.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <signal.h>
#include <ucontext.h>
#include <errno.h>

#define LOG_TAG "Perfare"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// =============================================================
// 全局变量
// =============================================================
int g_perf_fd = -1;
uintptr_t g_target_addr = 0;

// Hex 转字符串
std::string hexStr(unsigned char *data, int len) {
    std::stringstream ss;
    ss << std::hex;
    for (int i = 0; i < len; ++i)
        ss << std::setw(2) << std::setfill('0') << (int)data[i] << " ";
    return ss.str();
}

// =============================================================
// 信号处理 (中断发生时执行这里)
// =============================================================
void BreakpointHandler(int signum, siginfo_t *info, void *context) {
    ucontext_t *uc = (ucontext_t *)context;
    
    // 获取当前指令地址 (PC)
    #if defined(__aarch64__)
    uintptr_t pc = uc->uc_mcontext.pc;
    // 参数1 (this) = x0, 参数2 (packet) = x1
    uintptr_t arg1_packet = uc->uc_mcontext.regs[1]; 
    #elif defined(__arm__)
    uintptr_t pc = uc->uc_mcontext.arm_pc;
    uintptr_t arg1_packet = uc->uc_mcontext.arm_r1;
    #else
    uintptr_t pc = 0;
    uintptr_t arg1_packet = 0;
    #endif

    // 判断是否命中目标
    if (pc == g_target_addr) {
        LOGI(">>> [硬件断点命中] PC: %p <<<", (void*)pc);
        
        if (arg1_packet != 0) {
            // 打印数据！(尝试读取前 64 字节)
            // 这里的强转读取有一定风险，如果崩溃请加内存检查逻辑
            unsigned char* ptr = (unsigned char*)arg1_packet;
            LOGI("Packet Addr: %p", ptr);
            LOGI("Data: %s", hexStr(ptr, 64).c_str());
        }

        // 关键：命中一次后必须禁用，否则会死循环卡死在这里
        // 如果想持续抓包，需要实现单步调试(Single Step)机制，比较复杂
        // 这里为了演示成功，先禁用断点，让游戏继续运行
        if (g_perf_fd != -1) {
            ioctl(g_perf_fd, PERF_EVENT_IOC_DISABLE, 0);
            LOGI(">>> 断点已临时禁用，防止死循环 (单次抓取成功) <<<");
        }
    }
}

// =============================================================
// 设置硬件断点 (perf_event_open)
// =============================================================
void SetupHWBP(uintptr_t addr) {
    struct perf_event_attr pe;
    memset(&pe, 0, sizeof(struct perf_event_attr));
    
    pe.type = PERF_TYPE_BREAKPOINT;
    pe.size = sizeof(struct perf_event_attr);
    pe.bp_type = HW_BREAKPOINT_X; // 监控执行 (Execute)
    pe.bp_addr = addr;
    pe.bp_len = sizeof(long);
    pe.disabled = 1; // 初始关闭
    pe.exclude_kernel = 1;
    pe.exclude_hv = 1;

    // 为当前线程设置断点
    // 注意：硬件断点是线程级的！如果游戏逻辑不在这个线程，可能抓不到。
    // 但 Zygisk 注入通常有机会在主线程环境执行。
    g_perf_fd = syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
    
    if (g_perf_fd == -1) {
        LOGI("硬件断点创建失败: %s (Errno: %d)", strerror(errno), errno);
        return;
    }

    // 注册信号处理函数
    struct sigaction sa;
    memset(&sa, 0, sizeof(struct sigaction));
    sa.sa_sigaction = BreakpointHandler;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER; // SA_NODEFER 允许在处理函数内再次触发信号
    sigaction(SIGTRAP, &sa, NULL);

    // 启用断点
    ioctl(g_perf_fd, PERF_EVENT_IOC_ENABLE, 0);
    LOGI(">>> 硬件断点已激活，目标: %p (FD: %d) <<<", (void*)addr, g_perf_fd);
}

// =============================================================
// 寻找基址逻辑 (90MB大文件策略)
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
                // 大于 30MB
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
    LOGI(">>> HACK START: 纯净硬件断点模式 <<<");

    void* base_addr = nullptr;
    
    // 1. 找基址
    while (true) {
        base_addr = FindRealIl2CppBase();
        if (base_addr != nullptr) {
            LOGI("!!! 锁定真身 !!! Base Address: %p", base_addr);
            break;
        }
        sleep(1);
    }

    // 2. 计算目标地址
    // 你的 dump.cs 里的 PacketEncode 偏移
    uintptr_t offset_PacketEncode = 0x11b54c8; 
    g_target_addr = (uintptr_t)base_addr + offset_PacketEncode;
    
    LOGI(">>> 准备下断点: %p <<<", (void*)g_target_addr);

    // 3. 验证一下是不是真的代码 (OpCode 验证)
    unsigned char* code = (unsigned char*)g_target_addr;
    LOGI("OpCode Check: %02x %02x %02x %02x (应为 fb 6b bb a9)", code[0], code[1], code[2], code[3]);

    // 4. 设置硬件断点
    // 警告：如果 hack_start 是在独立线程运行的，这里的断点可能抓不到主线程的游戏逻辑。
    // 但这是“不加 Dobby”的唯一办法。如果抓不到，说明需要切线程，那个更麻烦。
    // 先试这个！
    SetupHWBP(g_target_addr);

    while(true) sleep(10);
}

// -----------------------------------------------------------
// 模板代码 (保持不变)
// -----------------------------------------------------------
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
