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
// 全局变量
// =============================================================
uintptr_t g_target_addr = 0;
uint32_t g_backup_instruction = 0;
volatile bool g_is_hook_active = false; // 标记当前是否下了钩子

// Hex 工具
std::string hexStr(unsigned char *data, int len) {
    std::stringstream ss;
    ss << std::hex;
    for (int i = 0; i < len; ++i)
        ss << std::setw(2) << std::setfill('0') << (int)data[i] << " ";
    return ss.str();
}

// =============================================================
// 信号处理器 (极速版 - 拒绝死锁)
// =============================================================
void TrapHandler(int signum, siginfo_t *info, void *context) {
    #if defined(__aarch64__)
    ucontext_t *uc = (ucontext_t *)context;
    uintptr_t pc = uc->uc_mcontext.pc;
    
    // 只有地址匹配才处理
    if (pc == g_target_addr) {
        
        // 1. 获取数据 (参数2 = x1)
        uintptr_t x1_packet = uc->uc_mcontext.regs[1];
        
        // 打印 (放在这里虽然理论上有风险，但通常没事，比 mprotect 安全得多)
        if (x1_packet > 0x10000) {
             // 尝试解包: Packet(x1) -> Buffer(+0x10) -> Data(+0x20)
             uintptr_t buffer_ptr = *(uintptr_t*)(x1_packet + 0x10);
             if (buffer_ptr > 0x10000) {
                 unsigned char* data = (unsigned char*)(buffer_ptr + 0x20);
                 LOGI(">>> [Data] %s", hexStr(data, 64).c_str());
             }
        }

        // 2. 还原指令 (最关键的一步)
        // 直接写内存，不调用 mprotect！
        *(uint32_t*)g_target_addr = g_backup_instruction;

        // 3. 刷新 CPU 缓存
        __builtin___clear_cache((char*)g_target_addr, (char*)g_target_addr + 4);
        
        // 4. 标记失效，通知主线程一会再来补钩子
        g_is_hook_active = false;
    }
    #endif
}

// =============================================================
// 激活钩子
// =============================================================
void ActivateHook() {
    if (g_target_addr == 0 || g_is_hook_active) return;

    // 写入中断指令 BRK #0
    #if defined(__aarch64__)
    *(uint32_t*)g_target_addr = 0xD4200000;
    #endif

    __builtin___clear_cache((char*)g_target_addr, (char*)g_target_addr + 4);
    g_is_hook_active = true;
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
// 主线程
// =============================================================
void hack_start(const char *game_data_dir) {
    LOGI(">>> HACK START: 极速采样版 (修复卡死) <<<");

    // 1. 注册信号
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
    
    g_target_addr = (uintptr_t)base_addr + 0x11b54c8;
    LOGI(">>> 目标锁定: %p <<<", (void*)g_target_addr);

    // 3. 【关键】一次性修改权限
    // 提前把这块地变成“可写”，以后 TrapHandler 里就不用改了，防止死锁
    void *page_start = (void *)(g_target_addr & ~(getpagesize() - 1));
    mprotect(page_start, getpagesize(), PROT_READ | PROT_WRITE | PROT_EXEC);
    
    // 备份原始指令
    g_backup_instruction = *(uint32_t*)g_target_addr;
    LOGI(">>> 备份指令: %08x <<<", g_backup_instruction);

    // 4. 循环下钩子
    while (true) {
        // 如果钩子被还原了(说明刚抓到了包)，休息 3 秒再下
        // 这样保证游戏有 3 秒的完全流畅时间
        if (!g_is_hook_active) {
            sleep(3); 
            ActivateHook();
            // LOGI(">>> 钩子已重置 <<<");
        } else {
            // 如果钩子还在(说明没发包)，就等着
            usleep(100000); // 0.1秒检查一次
        }
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
