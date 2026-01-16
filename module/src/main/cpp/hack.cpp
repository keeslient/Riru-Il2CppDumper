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
static char target_so_name[256] = {0}; // 自动识别到的乱码 SO 名字

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

        mprotect((void*)(real_sbox_addr & ~0xFFF), 4096, PROT_READ);
        real_sbox_addr = 0; // 销毁陷阱，防止卡顿
        LOGI("[✅] 关键数据已提取，任务完成。");
        LOGI("==================================================");
    }
}

// --- 3. 核心：S-Box 猎杀 (严格白名单版) ---
void scan_and_trap_real_sbox() {
    LOGI("[📡] 启动精准狙击模式 (过滤系统与Java层)...");
    
    // 延时 8 秒，确保游戏 Native 层加载完毕
    sleep(8);

    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return;
    
    char line[1024];
    uint32_t sbox_sig = 0x7B777C63; 
    
    while (fgets(line, sizeof(line), fp)) {
        // 【1】黑名单：绝对过滤掉所有系统库和 Java 虚拟机相关
        if (strstr(line, "/system/") || strstr(line, "/apex/") || strstr(line, "/vendor/") ||
            strstr(line, "dalvik")   || strstr(line, "art")    || strstr(line, "base.apk") || 
            strstr(line, "cache")    || strstr(line, "fonts")) {
            continue;
        }

        // 【2】白名单：只扫描两类目标
        // A. 那个乱码 SO (如果已经识别到了名字)
        // B. 匿名堆内存 [anon:libc_malloc] (LIAPP 动态解密区)
        bool is_target = false;
        
        if (strlen(target_so_name) > 0 && strstr(line, target_so_name)) {
            is_target = true;
        }
        else if (strstr(line, "[anon:libc_malloc]") || strstr(line, "[heap]")) {
            is_target = true;
        }
        // 如果名字是乱码的 SO (通常在 /data/app 下且名字奇怪)，也算目标
        else if (strstr(line, "/data/app") && strstr(line, ".so") && 
                 !strstr(line, "libmain.so") && !strstr(line, "libunity.so")) {
            is_target = true;
        }

        if (!is_target) continue;

        // 开始扫描
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
                            LOGI("[🔥] 锁定目标 S 盒！地址: %p", (void*)addr);
                            LOGI("[ℹ️] 来源确认: %s", line); // 必须是 libc_malloc 或 乱码SO 才行
                            
                            real_sbox_addr = addr;
                            struct sigaction sa;
                            memset(&sa, 0, sizeof(sa));
                            sa.sa_flags = SA_SIGINFO;
                            sa.sa_sigaction = sbox_trap_handler;
                            sigaction(SIGSEGV, &sa, NULL);
                            
                            if (mprotect((void*)(real_sbox_addr & ~0xFFF), 4096, PROT_NONE) == 0) {
                                LOGI("[🪤] 狙击陷阱已就位！");
                                fclose(fp);
                                return;
                            }
                        }
                    }
                }
            }
        }
    }
    fclose(fp);
    LOGI("[⚠️] 扫描完成，未发现符合严格过滤条件的目标。");
}

// --- 4. 启动入口 ---
void hack_start(const char *game_data_dir) {
    LOGI("[🚀] LIAPP 猎杀器启动...");
    
    // 自动识别乱码 SO 名字，用于辅助过滤
    for (int i = 0; i < 20; i++) {
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
                        LOGI("[ℹ️] 自动识别目标 SO: %s", target_so_name);
                        break;
                    }
                }
            }
            fclose(fp);
        }
        if (strlen(target_so_name) > 0) break;
        usleep(500000);
    }

    // 启动猎杀线程
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
    LOGI("[🔗] Zygisk 注入成功");
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
