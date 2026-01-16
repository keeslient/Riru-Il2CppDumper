#include "hack.h"
#include "log.h"
#include "xdl.h"
#include "And64InlineHook.hpp" 
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
#include <unwind.h> // 必须引用

#define LOG_TAG "Perfare"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// =============================================================
// 堆栈打印功能
// =============================================================
struct BacktraceState {
    void** current;
    void** end;
};

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

void PrintStackTrace() {
    const size_t max = 30;
    void* buffer[max];

    BacktraceState state = {buffer, buffer + max};
    _Unwind_Backtrace(UnwindCallback, &state);

    size_t count = state.current - buffer;

    LOGI("========== CALL STACK START ==========");
    for (size_t i = 0; i < count; ++i) {
        uintptr_t addr = (uintptr_t)buffer[i];
        
        Dl_info info;
        if (dladdr((void*)addr, &info) && info.dli_fname) {
            // 计算相对偏移
            uintptr_t offset = addr - (uintptr_t)info.dli_fbase;
            
            // 过滤：只看 libil2cpp.so
            if (strstr(info.dli_fname, "libil2cpp.so")) {
                // 【修复】这里强制强转为 unsigned long，解决 32 位编译报错
                LOGI("#%02zu PC: %p  (libil2cpp.so + 0x%lx)", i, (void*)addr, (unsigned long)offset);
            }
        } else {
            // LOGI("#%02zu PC: %p  (Unknown)", i, (void*)addr);
        }
    }
    LOGI("=========== CALL STACK END ===========");
}

// =============================================================
// Hex 工具
// =============================================================
std::string hexStr(unsigned char *data, int len) {
    std::stringstream ss;
    ss << std::hex;
    for (int i = 0; i < len; ++i)
        ss << std::setw(2) << std::setfill('0') << (int)data[i] << " ";
    return ss.str();
}

// =============================================================
// Hook 逻辑
// =============================================================
void (*old_PacketEncode)(void* instance, void* packet, bool flag);

void new_PacketEncode(void* instance, void* packet, bool flag) {
    
    // 防止刷屏，加入简单的频率控制
    static int call_count = 0;
    call_count++;

    if (packet != nullptr && (call_count % 10 == 0)) { // 每10次处理一次
        uintptr_t buffer_obj = *(uintptr_t*)((uintptr_t)packet + 0x10);
        
        if (buffer_obj > 0x10000) {
            uint32_t data_len = *(uint32_t*)(buffer_obj + 0x18);
            unsigned char* raw_data = (unsigned char*)(buffer_obj + 0x20);
            
            if (data_len > 0 && data_len < 4096) {
                LOGI(">>> [抓包] 长度: %d | Data: %s", data_len, hexStr(raw_data, (data_len > 64 ? 64 : data_len)).c_str());
                
                // 【调用栈】只打印一次，方便定位
                static bool stack_printed = false;
                if (!stack_printed) {
                    PrintStackTrace();
                    stack_printed = true;
                }
            }
        }
    }

    if(old_PacketEncode) old_PacketEncode(instance, packet, flag);
}

// =============================================================
// 辅助与主线程
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

void hack_start(const char *game_data_dir) {
    LOGI(">>> HACK START: And64InlineHook + CallStack <<<");

    void* base_addr = nullptr;
    while (base_addr == nullptr) {
        base_addr = FindRealIl2CppBase();
        sleep(1);
    }

    // 偏移量
    uintptr_t target_addr = (uintptr_t)base_addr + 0x11b54c8; 
    LOGI(">>> Hooking: %p <<<", (void*)target_addr);

    // 仅在 64 位下执行 Hook (And64InlineHook 不支持 32 位)
    #if defined(__aarch64__)
        A64HookFunction((void*)target_addr, (void*)new_PacketEncode, (void**)&old_PacketEncode);
        LOGI(">>> Hook 完成 (64-bit) <<<");
    #else
        LOGI(">>> 警告: 当前是 32 位环境，And64InlineHook 无法工作 <<<");
    #endif
    
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
