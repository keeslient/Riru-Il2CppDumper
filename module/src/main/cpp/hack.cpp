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

// --- 全局变量 ---
static uintptr_t global_so_base = 0;
static uintptr_t real_sbox_addr = 0; // 动态搜索到的真 S 盒

// --- 1. 内存嗅探辅助 (兼容 32/64 位) ---
void safe_hex_dump(const char* label, uintptr_t addr, size_t len) {
#if defined(__aarch64__)
    if (addr < 0x10000000 || addr > 0x7fffffffff) return;
#else
    if (addr < 0x1000000) return;
#endif

    unsigned char buf[64];
    size_t copy_len = len > 64 ? 64 : len;
    // 尝试读取
    if (memcpy(buf, (void*)addr, copy_len)) {
        char hex_out[256] = {0};
        for(size_t i = 0; i < copy_len; i++) {
            sprintf(hex_out + strlen(hex_out), "%02X ", buf[i]);
        }
        LOGI("[💎] %s (地址: %p) 内容: %s", label, (void*)addr, hex_out);
    }
}

// --- 2. 信号处理函数 (单次触发，绝不卡死) ---
void sbox_trap_handler(int sig, siginfo_t *info, void *context) {
    auto* ctx = (ucontext_t*)context;
    
    // 只有撞到我们锁定的那个真 S 盒才触发
    if ((uintptr_t)info->si_addr == real_sbox_addr && real_sbox_addr != 0) {
        LOGI("================ [🚨 抓到游戏加密现场] ================");
        
#if defined(__aarch64__)
        uintptr_t pc = ctx->uc_mcontext.pc;
        uintptr_t lr = ctx->uc_mcontext.regs[30];
        LOGI("[🎯] PC: %p, LR: %p (请在 IDA 跳转此 LR 地址)", (void*)pc, (void*)lr);
        
        // 打印 X0-X3 (Key 和 明文 通常在这里)
        safe_hex_dump("寄存器 X0", (uintptr_t)ctx->uc_mcontext.regs[0], 64);
        safe_hex_dump("寄存器 X1", (uintptr_t)ctx->uc_mcontext.regs[1], 64);
        safe_hex_dump("寄存器 X2", (uintptr_t)ctx->uc_mcontext.regs[2], 64);
        safe_hex_dump("寄存器 X3", (uintptr_t)ctx->uc_mcontext.regs[3], 64);
#elif defined(__arm__)
        uintptr_t pc = ctx->uc_mcontext.arm_pc;
        uintptr_t lr = ctx->uc_mcontext.arm_lr;
        LOGI("[🎯] PC: %p, LR: %p", (void*)pc, (void*)lr);
        // 32位看 R0-R3
        safe_hex_dump("寄存器 R0", (uintptr_t)ctx->uc_mcontext.arm_r0, 64);
        safe_hex_dump("寄存器 R1", (uintptr_t)ctx->uc_mcontext.arm_r1, 64);
#endif

        // 恢复权限，让游戏继续运行
        mprotect((void*)(real_sbox_addr & ~0xFFF), 4096, PROT_READ);

        // 【关键】防止卡死的逻辑：
        // 既然已经抓到了现场，我们直接把陷阱废掉。
        // 不需要再重新 mprotect(PROT_NONE) 了。
        real_sbox_addr = 0; 
        
        LOGI("[✅] 关键数据已提取，陷阱已永久解除，游戏恢复正常。");
        LOGI("==================================================");
    }
}

// --- 3. 核心：智能 S 盒猎杀 (带白名单过滤) ---
void scan_and_trap_real_sbox() {
    LOGI("[📡] 启动智能 S-Box 猎杀 (已开启系统库过滤)...");
    
    // 给游戏一点时间解密 S 盒 (5秒)
    sleep(5);

    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return;
    
    char line[1024];
    // AES S-Box 前 4 字节固定特征: 63 7C 77 7B
    uint32_t sbox_sig = 0x7B777C63; 
    
    while (fgets(line, sizeof(line), fp)) {
        // 【关键过滤】绝对不要碰系统库，否则手机会卡死
        if (strstr(line, "/system/") || strstr(line, "/apex/") || strstr(line, "/vendor/")) {
            continue;
        }

        // 只扫描可读写段 (rw-p)，通常动态 S 盒藏在 [anon:libc_malloc] 或游戏 SO 的 BSS 段
        if (strstr(line, "rw-p")) {
            unsigned long tmp_start, tmp_end;
            // 使用 unsigned long 兼容 32/64 位编译
            if (sscanf(line, "%lx-%lx", &tmp_start, &tmp_end) == 2) {
                uintptr_t start = (uintptr_t)tmp_start;
                uintptr_t end = (uintptr_t)tmp_end;

                // 过滤掉太小的段
                if (end - start < 4096) continue;

                // 暴力扫描该段
                for (uintptr_t addr = start; addr < end - 16; addr += 4) {
                    // 检查特征
                    if (*(uint32_t*)addr == sbox_sig) {
                        unsigned char* p = (unsigned char*)addr;
                        // 二次特征检查 (第16字节是否为 63)
                        // S-Box: 63 7C 77 7B ... [15]=?
                        // 这里我们检查 p[4]=F2, p[5]=6B 增加准确性
                        if (p[4] == 0xF2 && p[5] == 0x6B) {
                            LOGI("[🔥] 在游戏私有内存发现 S 盒！地址: %p", (void*)addr);
                            LOGI("[ℹ️] 内存段来源: %s", line); 
                            
                            real_sbox_addr = addr;
                            
                            struct sigaction sa;
                            memset(&sa, 0, sizeof(sa));
                            sa.sa_flags = SA_SIGINFO;
                            sa.sa_sigaction = sbox_trap_handler;
                            sigaction(SIGSEGV, &sa, NULL);
                            
                            // 布下陷阱
                            if (mprotect((void*)(real_sbox_addr & ~0xFFF), 4096, PROT_NONE) == 0) {
                                LOGI("[🪤] 陷阱已布设 (单次模式)！请立刻进入游戏操作发包...");
                                fclose(fp);
                                return; // 找到一个最像的就收手，避免多重陷阱
                            } else {
                                LOGI("[❌] 布设失败，可能是权限不足。");
                            }
                        }
                    }
                }
            }
        }
    }
    fclose(fp);
    LOGI("[⚠️] 扫描结束，未发现符合条件的目标。");
}

// --- 4. 启动入口 ---
void hack_start(const char *game_data_dir) {
    LOGI("[🚀] 最终猎杀版启动...");
    
    // 启动 S 盒扫描线程
    std::thread(scan_and_trap_real_sbox).detach();

    // 启动 il2cpp dump (保留功能)
    void *handle = xdl_open("libil2cpp.so", 0);
    if (handle) {
        il2cpp_api_init(handle);
        il2cpp_dump(game_data_dir);
    }
}

// --- 5. 接口定义 ---
void hack_prepare(const char *game_data_dir, void *data, size_t length) {
    LOGI("[🔗] Zygisk 调用 hack_prepare...");
    std::string path = game_data_dir ? game_data_dir : "";
    std::thread([path]() {
        hack_start(path.c_str());
    }).detach();
}

#if defined(__arm__) || defined(__aarch64__)
extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    hack_prepare((const char*)reserved, nullptr, 0);
    return JNI_VERSION_1_6;
}
#endif
