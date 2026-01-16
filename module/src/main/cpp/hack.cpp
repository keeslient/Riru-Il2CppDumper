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
static uintptr_t real_sbox_addr = 0; 
static char target_so_name[256] = {0}; 

// --- 1. 内存嗅探 ---
void safe_hex_dump(const char* label, uintptr_t addr, size_t len) {
#if defined(__aarch64__)
    if (addr < 0x10000000 || addr > 0x7fffffffff) return;
#else
    if (addr < 0x1000000) return;
#endif
    unsigned char buf[64];
    size_t copy_len = len > 64 ? 64 : len;
    if (memcpy(buf, (void*)addr, copy_len)) {
        char hex_out[256] = {0};
        for(size_t i = 0; i < copy_len; i++) {
            sprintf(hex_out + strlen(hex_out), "%02X ", buf[i]);
        }
        LOGI("[💎] %s (地址: %p) 内容: %s", label, (void*)addr, hex_out);
    }
}

// --- 2. 信号处理 (单次触发) ---
void sbox_trap_handler(int sig, siginfo_t *info, void *context) {
    auto* ctx = (ucontext_t*)context;
    
    // 只有撞到真 S 盒才触发
    if ((uintptr_t)info->si_addr == real_sbox_addr && real_sbox_addr != 0) {
        LOGI("================ [🚨 抓到 LIAPP 加密现场] ================");
        
#if defined(__aarch64__)
        uintptr_t pc = ctx->uc_mcontext.pc;
        uintptr_t lr = ctx->uc_mcontext.regs[30];
        LOGI("[🎯] PC: %p, LR: %p (去 IDA 搜 LR!)", (void*)pc, (void*)lr);
        safe_hex_dump("寄存器 X0", (uintptr_t)ctx->uc_mcontext.regs[0], 64);
        safe_hex_dump("寄存器 X1", (uintptr_t)ctx->uc_mcontext.regs[1], 64);
        safe_hex_dump("寄存器 X2", (uintptr_t)ctx->uc_mcontext.regs[2], 64);
#elif defined(__arm__)
        uintptr_t pc = ctx->uc_mcontext.arm_pc;
        uintptr_t lr = ctx->uc_mcontext.arm_lr;
        LOGI("[🎯] PC: %p, LR: %p", (void*)pc, (void*)lr);
#endif

        // 恢复权限
        mprotect((void*)(real_sbox_addr & ~0xFFF), 4096, PROT_READ);
        real_sbox_addr = 0; // 销毁全局变量，停止监控
        LOGI("[✅] 陷阱已触发并解除，不再拦截。");
        LOGI("==================================================");
    }
}

// --- 3. 核心：死循环扫描 (直到找到为止) ---
void scan_and_trap_real_sbox() {
    LOGI("[📡] 启动持续监控模式 (每3秒扫描一次)...");
    
    uint32_t sbox_sig = 0x7B777C63; 
    
    // 【修改点】改为死循环，直到找到目标才退出
    while (real_sbox_addr == 0) {
        
        FILE* fp = fopen("/proc/self/maps", "r");
        if (!fp) {
            sleep(1);
            continue;
        }
        
        char line[1024];
        while (fgets(line, sizeof(line), fp)) {
            // 严格过滤系统库
            if (strstr(line, "/system/") || strstr(line, "/apex/") || strstr(line, "/vendor/") ||
                strstr(line, "dalvik")   || strstr(line, "art")    || strstr(line, "base.apk") || 
                strstr(line, "cache")    || strstr(line, "fonts")) {
                continue;
            }

            bool is_target = false;
            // 只看乱码 SO 或 堆内存
            if (strlen(target_so_name) > 0 && strstr(line, target_so_name)) is_target = true;
            else if (strstr(line, "[anon:libc_malloc]") || strstr(line, "[heap]")) is_target = true;
            else if (strstr(line, "/data/app") && strstr(line, ".so") && 
                     !strstr(line, "libmain.so") && !strstr(line, "libunity.so")) is_target = true;

            if (!is_target) continue;

            if (strstr(line, "rw-p")) {
                unsigned long tmp_start, tmp_end;
                if (sscanf(line, "%lx-%lx", &tmp_start, &tmp_end) == 2) {
                    uintptr_t start = (uintptr_t)tmp_start;
                    uintptr_t end = (uintptr_t)tmp_end;
                    if (end - start < 4096) continue;

                    for (uintptr_t addr = start; addr < end - 16; addr += 4) {
                        if (*(uint32_t*)addr == sbox_sig) {
                            unsigned char* p = (unsigned char*)addr;
                            if (p[4] == 0xF2 && p[5] == 0x6B) {
                                LOGI("[🔥] 终于等到你！地址: %p", (void*)addr);
                                LOGI("[ℹ️] 来源: %s", line);
                                
                                real_sbox_addr = addr;
                                struct sigaction sa;
                                memset(&sa, 0, sizeof(sa));
                                sa.sa_flags = SA_SIGINFO;
                                sa.sa_sigaction = sbox_trap_handler;
                                sigaction(SIGSEGV, &sa, NULL);
                                
                                if (mprotect((void*)(real_sbox_addr & ~0xFFF), 4096, PROT_NONE) == 0) {
                                    LOGI("[🪤] 陷阱布设成功！等待游戏触发...");
                                    fclose(fp);
                                    return; // 找到后退出函数，不再扫描
                                }
                            }
                        }
                    }
                }
            }
        }
        fclose(fp);
        
        // 没找到？休息3秒继续找，直到地老天荒
        if (real_sbox_addr == 0) {
            // LOGI("[💤] 本轮未发现，3秒后重试..."); // 调试时可开启
            sleep(3);
        }
    }
}

// --- 4. 启动入口 ---
void hack_start(const char *game_data_dir) {
    LOGI("[🚀] 猎杀者就绪...");
    
    // 持续尝试识别乱码 SO 名字
    std::thread([]() {
        while (strlen(target_so_name) == 0) {
            FILE* fp = fopen("/proc/self/maps", "r");
            if (fp) {
                char line[1024];
                while (fgets(line, sizeof(line), fp)) {
                    if (strstr(line, ".so") && strstr(line, "/data/app") && 
                        !strstr(line, "libmain.so") && !strstr(line, "libunity.so") && 
                        !strstr(line, "libil2cpp.so")) {
                        
                        char* so_path = strchr(line, '/');
                        char* so_name = strrchr(so_path, '/');
                        if (so_name) {
                            so_name++;
                            so_name[strcspn(so_name, "\n")] = 0;
                            strncpy(target_so_name, so_name, 255);
                            LOGI("[ℹ️] 目标锁定: %s", target_so_name);
                            break;
                        }
                    }
                }
                fclose(fp);
            }
            if (strlen(target_so_name) == 0) sleep(1);
        }
    }).detach();

    // 启动死循环扫描线程
    std::thread(scan_and_trap_real_sbox).detach();

    // il2cpp dump
    void *handle = xdl_open("libil2cpp.so", 0);
    if (handle) {
        il2cpp_api_init(handle);
        il2cpp_dump(game_data_dir);
    }
}

// --- 5. 接口 ---
void hack_prepare(const char *game_data_dir, void *data, size_t length) {
    LOGI("[🔗] Zygisk 注入成功，后台线程已启动");
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
