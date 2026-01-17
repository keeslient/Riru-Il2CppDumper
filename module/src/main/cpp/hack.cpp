#include "hack.h"
#include "il2cpp_dump.h"
#include "log.h"
#include "xdl.h"
#include "shadowhook.h" // 必须包含
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
#include <iomanip>
#include <sstream>

// --- 定义 Hook 相关的变量 ---
typedef void* (*PacketEncode_t)(void* instance, void* packet, char a3);
PacketEncode_t old_PacketEncode = nullptr;

// 十六进制转换工具函数
std::string bytesToHex(uint8_t* data, uint32_t len) {
    if (!data || len == 0) return "Empty";
    std::stringstream ss;
    for (uint32_t i = 0; i < len; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i] << " ";
    }
    return ss.str();
}

// --- 我们的明文拦截器函数 ---
void* new_PacketEncode(void* instance, void* packet, char a3) {
    if (packet != nullptr) {
        // 根据之前的 sub 函数分析层层寻找明文数据
        // Packet -> MemoryStream(0x10) -> byte[] Array(0x10)
        uintptr_t* stream_ptr = (uintptr_t*)((uintptr_t)packet + 0x10);
        
        if (stream_ptr && (uintptr_t)*stream_ptr > 0x100000) {
            uintptr_t* array_ptr = (uintptr_t*)(*stream_ptr + 0x10);
            
            if (array_ptr && (uintptr_t)*array_ptr > 0x100000) {
                // IL2CPP 数组结构：0x18是长度, 0x20是数据
                uint32_t len = *(uint32_t*)(*array_ptr + 0x18);
                uint8_t* data = (uint8_t*)(*array_ptr + 0x20);

                if (len > 0 && len < 4096) {
                    LOGI("================ [捕获明文封包] ================");
                    LOGI("长度: %u, 模式(a3): %d", len, (int)a3);
                    
                    // 读取滚动 Key (instance + 0x10)
                    if (instance) {
                        uint8_t current_key = *(uint8_t*)((uintptr_t)instance + 16);
                        LOGI("当前 Rolling Key: 0x%02X", current_key);
                    }
                    
                    LOGI("内容: %s", bytesToHex(data, len).c_str());
                    LOGI("===============================================");
                }
            }
        }
    }
    // 调用原函数，保证游戏逻辑正常
    return old_PacketEncode(instance, packet, a3);
}

void hack_start(const char *game_data_dir) {
    LOGI("hack_start thread: %d", gettid());
    bool load = false;
    
    // 初始化 ShadowHook
    if (shadowhook_init() != 0) {
        LOGE("ShadowHook init failed!");
    }

    for (int i = 0; i < 15; i++) { // 延长一点等待时间
        void *handle = xdl_open("libil2cpp.so", 0);
        if (handle) {
            load = true;
            LOGI("libil2cpp.so found at handle: %p", handle);

            // 获取 il2cpp 基址
            xdl_info_t info;
            if (xdl_info(handle, XDL_DI_DLINFO, &info)) {
                void* il2cpp_base = info.dli_fbase;
                LOGI("libil2cpp.so Base: %p", il2cpp_base);

                // --- 在这里执行 Hook ---
                void* target_addr = (void*)((uintptr_t)il2cpp_base + 0x11B54C8);
                LOGI("Hooking Target: %p", target_addr);

                shadowhook_hook_func(target_addr, (void*)new_PacketEncode, (void**)&old_PacketEncode);
                
                if (old_PacketEncode != nullptr) {
                    LOGI(">>> Hook 成功！正在捕获明文包...");
                } else {
                    LOGE(">>> Hook 失败！错误码: %d", shadowhook_get_errno());
                }
            }

            // 保留你原本的 dump 功能
            il2cpp_api_init(handle);
            il2cpp_dump(game_data_dir);
            
            xdl_close(handle);
            break;
        } else {
            sleep(1);
        }
    }
    if (!load) {
        LOGI("libil2cpp.so not found in thread %d", gettid());
    }
}

// ... 这里的 GetLibDir, GetNativeBridgeLibrary, NativeBridgeLoad, hack_prepare 保持你提供的原样 ...

std::string GetLibDir(JavaVM *vms) {
    // 你的原版 GetLibDir 代码... (此处省略，保持你提供的原文)
    // [直接粘贴你刚才发的 GetLibDir 函数内容]
}

// ... 后续代码完全保持你原本发送的版本即可 ...

#if defined(__arm__) || defined(__aarch64__)
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    auto game_data_dir = (const char *) reserved;
    std::thread hack_thread(hack_start, game_data_dir);
    hack_thread.detach();
    return JNI_VERSION_1_6;
}
#endif
