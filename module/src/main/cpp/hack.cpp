#include "hack.h"
#include "log.h"
#include "xdl.h"
#include "And64InlineHook.hpp" // 引用本地的头文件
#include <cstring>
#include <cstdio>
#include <unistd.h>
#include <dlfcn.h>
#include <jni.h>
#include <thread>
#include <sys/mman.h>
#include <android/log.h>
#include <vector>
#include <iomanip>
#include <sstream>
#include <unwind.h>
#include <dlfcn.h>
#define LOG_TAG "Perfare"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// Hex 工具
std::string hexStr(unsigned char *data, int len) {
    std::stringstream ss;
    ss << std::hex;
    for (int i = 0; i < len; ++i)
        ss << std::setw(2) << std::setfill('0') << (int)data[i] << " ";
    return ss.str();
}
// =============================================================
// 堆栈回溯结构体
// =============================================================
struct BacktraceState {
    void** current;
    void** end;
};

// 回调函数：由 _Unwind_Backtrace 每一层调用一次
_Unwind_Reason_Code UnwindCallback(struct _Unwind_Context* context, void* arg) {
    BacktraceState* state = static_cast<BacktraceState*>(arg);
    uintptr_t pc = _Unwind_GetIP(context);
    if (pc) {
        if (state->current == state->end) {
            return _URC_END_OF_STACK;
        } else {
            *state->current++ = reinterpret_cast<void*>(pc);
        }
    }
    return _URC_NO_REASON;
}

// =============================================================
// 【核心功能】打印当前调用栈
// =============================================================
void PrintStackTrace() {
    const size_t max = 30; // 最多打印 30 层
    void* buffer[max];

    BacktraceState state = {buffer, buffer + max};
    _Unwind_Backtrace(UnwindCallback, &state);

    size_t count = state.current - buffer;

    // 获取 libil2cpp.so 的基址，用来计算偏移
    // 注意：这里复用了你之前写的 FindRealIl2CppBase 逻辑
    // 如果那个函数没存全局变量，建议弄个全局变量 g_il2cpp_base
    // 这里为了演示，我假设你有一个全局变量 g_il2cpp_base
    // 如果没有，你需要先获取一下，或者直接用 dl_iterate_phdr 找
    // 简单起见，我们打印绝对地址，你去 IDA 里减去基址也行
    
    LOGI("========== CALL STACK START ==========");
    
    for (size_t i = 0; i < count; ++i) {
        uintptr_t addr = (uintptr_t)buffer[i];
        
        // 尝试获取符号信息 (如果有的话，release版通常没有)
        Dl_info info;
        if (dladdr((void*)addr, &info) && info.dli_fname) {
            // 计算相对偏移： 绝对地址 - 模块基址
            uintptr_t offset = addr - (uintptr_t)info.dli_fbase;
            
            // 只打印 libil2cpp.so 里的调用，过滤掉系统的
            if (strstr(info.dli_fname, "libil2cpp.so")) {
                LOGI("#%02zu PC: %p  (libil2cpp.so + 0x%lx)", i, (void*)addr, offset);
            } else {
                // 其他库（比如系统库或 art）
                // LOGI("#%02zu PC: %p  (%s)", i, (void*)addr, info.dli_fname);
            }
        } else {
            LOGI("#%02zu PC: %p  (Unknown)", i, (void*)addr);
        }
    }
    LOGI("=========== CALL STACK END ===========");
}
// 定义原函数指针
void (*old_PacketEncode)(void* instance, void* packet, bool flag);

// 新函数 (完全不卡顿版)
void new_PacketEncode(void* instance, void* packet, bool flag) {
    
    if (packet != nullptr) {
        // 1. 获取 Buffer 对象 (0x10)
        uintptr_t buffer_obj = *(uintptr_t*)((uintptr_t)packet + 0x10);
        
        if (buffer_obj > 0x10000) {
            // 2. 验证长度 (0x18)
            // C# 数组的长度是一个 32位整数，在 0x18 位置
            uint32_t data_len = *(uint32_t*)(buffer_obj + 0x18);
            
            // 3. 获取数据 (0x20)
            unsigned char* raw_data = (unsigned char*)(buffer_obj + 0x20);
            
            // 过滤：只有长度 > 0 且 < 4096 (防止异常大包刷屏) 才打印
            if (data_len > 0 && data_len < 4096) {
                LOGI(">>> [抓包] 长度: %d | Data: %s", data_len, hexStr(raw_data, (data_len > 64 ? 64 : data_len)).c_str());
            }
        }
        static bool printed = false;
    if (!printed) {
        LOGI(">>> 捕获到函数调用，开始回溯堆栈... <<<");
        PrintStackTrace();
        printed = true; // 只打一次，打完收工
    }

    // 调用原函数
    if(old_PacketEncode) old_PacketEncode(instance, packet, flag);
    }

    // 调用原函数，保证游戏逻辑正常
    if(old_PacketEncode) old_PacketEncode(instance, packet, flag);
}

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

void hack_start(const char *game_data_dir) {
    LOGI(">>> HACK START: And64InlineHook 极速模式 <<<");

    void* base_addr = nullptr;
    while (base_addr == nullptr) {
        base_addr = FindRealIl2CppBase();
        sleep(1);
    }

    uintptr_t target_addr = (uintptr_t)base_addr + 0x11b54c8; 
    LOGI(">>> Hooking: %p <<<", (void*)target_addr);

    // 使用 And64InlineHook 进行挂钩
    // 这种方式不会暂停线程，所以游戏绝对流畅
    A64HookFunction((void*)target_addr, (void*)new_PacketEncode, (void**)&old_PacketEncode);
    
    LOGI(">>> Hook 完成，请操作游戏看日志 <<<");
    
    // 保持线程，防止 so 被卸载
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
