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
#include <signal.h>
#include <ucontext.h>
#include <vector>

#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG "IMO_NINJA"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// 全局变量
static uintptr_t global_so_base = 0;
static uintptr_t real_sbox_addr = 0; // 动态搜索到的真 S 盒

// 内存嗅探辅助
void safe_hex_dump(const char* label, uintptr_t addr, size_t len) {
    if (addr < 0x10000000 || addr > 0x7fffffffff) return;
    unsigned char buf[64];
    // 尝试读取，如果地址非法可能会崩溃，所以仅在 trap 中使用较安全
    memcpy(buf, (void*)addr, len > 32 ? 32 : len);
    char hex_out[128] = {0};
    for(size_t i = 0; i < (len > 32 ? 32 : len); i++) {
        sprintf(hex_out + strlen(hex_out), "%02X ", buf[i]);
    }
    LOGI("[💎] %s (地址: %p) 内容: %s", label, (void*)addr, hex_out);
}

// --- 1. 信号处理函数 ---
void sbox_trap_handler(int sig, siginfo_t *info, void *context) {
    auto* ctx = (ucontext_t*)context;
    
    // 只有撞到我们锁定的那个真 S 盒才触发
    if ((uintptr_t)info->si_addr == real_sbox_addr) {
        LOGI("================ [🚨 抓到活的加密现场] ================");
        
#if defined(__aarch64__)
        uintptr_t pc = ctx->uc_mcontext.pc;
        uintptr_t lr = ctx->uc_mcontext.regs[30];
        LOGI("[🎯] PC: %p, LR: %p (追踪此地址!)", (void*)pc, (void*)lr);
        
        // 打印 X0-X3，明文大概率在这里
        safe_hex_dump("寄存器 X0", (uintptr_t)ctx->uc_mcontext.regs[0], 32);
        safe_hex_dump("寄存器 X1", (uintptr_t)ctx->uc_mcontext.regs[1], 32);
        safe_hex_dump("寄存器 X2", (uintptr_t)ctx->uc_mcontext.regs[2], 32);
#elif defined(__arm__)
        uintptr_t pc = ctx->uc_mcontext.arm_pc;
        uintptr_t lr = ctx->uc_mcontext.arm_lr;
        LOGI("[🎯] PC: %p, LR: %p", (void*)pc, (void*)lr);
#endif

        // 临时恢复权限
        mprotect((void*)(real_sbox_addr & ~0xFFF), 4096, PROT_READ);

        // 异步重置陷阱，持续监控
        std::thread([]() {
            usleep(20000); // 20ms 后重新布防
            if (real_sbox_addr != 0) {
                mprotect((void*)(real_sbox_addr & ~0xFFF), 4096, PROT_NONE);
            }
        }).detach();

        LOGI("==================================================");
    }
}

// --- 2. 核心：全内存搜索 S 盒特征 ---
// LIAPP 可能会在 Heap 动态生成 S 盒，静态地址往往是诱饵
void scan_and_trap_real_sbox() {
    LOGI("[📡] 启动全内存 S-Box 猎杀...");
    
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return;
    
    char line[1024];
    // AES S-Box 前 4 字节固定特征
    uint32_t sbox_sig = 0x7B777C63; // 63 7C 77 7B (小端序)
    
    while (fgets(line, sizeof(line), fp)) {
        // 只扫描可读写 (rw-) 的段，这通常是 Heap 或 Stack，也是动态 S 盒藏身之处
        if (strstr(line, "rw-p")) {
            uintptr_t start, end;
            if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
                // 过滤掉太小的段或系统段，提高效率
                if (end - start < 4096) continue;
                
                // 暴力扫描该段
                for (uintptr_t addr = start; addr < end - 16; addr += 4) {
                    // 使用 mincore 或直接 try-catch 会更稳，但这里假设 maps 准确
                    // 简单检查前4字节
                    if (*(uint32_t*)addr == sbox_sig) {
                        // 二次检查：检查第 16 个字节是否为 63 (S[0]=0x63, S[15] is different)
                        // S-Box: 63 7C 77 7B F2 6B 6F C5 ...
                        unsigned char* p = (unsigned char*)addr;
                        if (p[4] == 0xF2 && p[5] == 0x6B) {
                            LOGI("[🔥] 发现疑似动态 S 盒！地址: %p", (void*)addr);
                            
                            // 排除掉那个假的静态 S 盒 (如果你知道它的范围)
                            // 布下陷阱
                            real_sbox_addr = addr;
                            
                            struct sigaction sa;
                            memset(&sa, 0, sizeof(sa));
                            sa.sa_flags = SA_SIGINFO;
                            sa.sa_sigaction = sbox_trap_handler;
                            sigaction(SIGSEGV, &sa, NULL);
                            
                            if (mprotect((void*)(real_sbox_addr & ~0xFFF), 4096, PROT_NONE) == 0) {
                                LOGI("[🪤] 成功在动态 S 盒上布雷！等待触发...");
                                fclose(fp); // 找到一个就收工，避免多重陷阱崩溃
                                return;
                            }
                        }
                    }
                }
            }
        }
    }
    fclose(fp);
    LOGI("[❌] 内存扫描结束，未找到动态 S 盒。可能使用了硬件 AES 指令。");
}

// --- 3. 启动入口 ---
void hack_start(const char *game_data_dir) {
    LOGI("[🚀] 动态猎杀版启动...");
    
    // 先尝试获取核心库基址 (辅助定位)
    for (int i = 0; i < 10; i++) {
        FILE* fp = fopen("/proc/self/maps", "r");
        if (fp) {
            char line[1024];
            while (fgets(line, sizeof(line), fp)) {
                if (strstr(line, "libfvctyud.so")) { // 你的乱码 SO 名
                    global_so_base = strtoull(line, nullptr, 16);
                    LOGI("[ℹ️] 核心库基址: %p", (void*)global_so_base);
                    break;
                }
            }
            fclose(fp);
        }
        if (global_so_base) break;
        sleep(1);
    }

    // 无论找没找到 SO，都直接启动全内存搜索
    // 因为动态 S 盒可能在堆里，不在 SO 段里
    std::thread(scan_and_trap_real_sbox).detach();

    // 保留 il2cpp dump 逻辑
    void *handle = xdl_open("libil2cpp.so", 0);
    if (handle) {
        il2cpp_api_init(handle);
        il2cpp_dump(game_data_dir);
    }
}

// --- 4. 修复链接错误的 Zygisk 接口 ---
void hack_prepare(const char *game_data_dir, void *data, size_t length) {
    LOGI("[🔗] Zygisk 调用 hack_prepare...");
    std::string path = game_data_dir ? game_data_dir : "";
    std::thread([path]() {
        // 延迟一点启动，等游戏解密出真正的 S 盒
        sleep(5); 
        hack_start(path.c_str());
    }).detach();
}

#if defined(__arm__) || defined(__aarch64__)
extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    hack_prepare((const char*)reserved, nullptr, 0);
    return JNI_VERSION_1_6;
}
#endif
