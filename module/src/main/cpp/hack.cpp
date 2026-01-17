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
#include <string>
#include <sstream>
#include <iomanip>

// --- 强制日志宏 ---
#undef LOG_TAG
#define LOG_TAG "Perfare_Packet"
#undef LOGI
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// --- 安全的 HexDump：防止空指针和长度异常 ---
std::string SafeHexDump(void* ptr, int len) {
    if (!ptr) return "NULL";
    // 64位 IL2CPP: byte[] 数据起始偏移通常是 0x20
    unsigned char* raw_data = (unsigned char*)ptr + 0x20; 
    std::stringstream ss;
    int safe_len = (len > 64) ? 64 : len; // 别打太长，容易刷屏
    for (int i = 0; i < safe_len; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)raw_data[i] << " ";
    }
    return ss.str();
}

// --- 拦截函数 ---
void* my_PacketEncode(void* instance, void* buffer, int length) {
    // 只要进来了，先打个最简单的标记，证明 Hook 活着
    LOGI(">>>> [!] PacketEncode 被调用了！长度: %d", length);
    
    if (buffer != nullptr && length > 0) {
        LOGI(">>>> [数据预览]: %s", SafeHexDump(buffer, length).c_str());
    }
    
    // 因为是暴力指令替换，执行完这里游戏必崩。
    // 但只要你在 log 里看到了上面这行，我们的目的就达到了。
    return nullptr; 
}

// --- ARM64 暴力指令替换 ---
void patch_hook_64(void* target, void* replace) {
    unsigned long page_size = sysconf(_SC_PAGESIZE);
    uintptr_t addr = (uintptr_t)target & ~(page_size - 1);
    mprotect((void*)addr, page_size * 2, PROT_READ | PROT_WRITE | PROT_EXEC);

    uint32_t* code = (uint32_t*)target;
    // ARM64 跳转: LDR X16, 8; BR X16; [ADDR_64]
    code[0] = 0x58000050; 
    code[1] = 0xd61f0200;
    *((void**)(code + 2)) = replace;
    
    __builtin___clear_cache((char*)target, (char*)target + 16);
}

void hack_start(const char *game_data_dir) {
    LOGI("Zygisk 业务线程启动...");
    sleep(15); 

    void *handle = xdl_open("libil2cpp.so", 0);
    if (handle) {
        LOGI("libil2cpp.so 已找到: %p", handle);
        
        il2cpp_api_init(handle);
        il2cpp_dump(game_data_dir);

        // --- 核心校验逻辑 ---
        // 1. 请务必确认这个 0x123456 是你从 dump.cs 里搜到的 PacketEncode 的 RVA 地址
        size_t packet_rva = 0x11b54c8; 
        void* target_addr = (void*)((uintptr_t)handle + packet_rva);
        
        // 2. 检查这个地址上到底是什么指令
        unsigned char* check = (unsigned char*)target_addr;
        LOGI("检查目标地址原始指令: %02X %02X %02X %02X", check[0], check[1], check[2], check[3]);
        
        /**
         * 经验提示：
         * 如果打印出是 00 00 00 00，说明偏移地址错了。
         * 如果是 FD 7B BF A9，说明这是标准的 ARM64 函数头（STP X29, X30...），稳了！
         */

        LOGI("开始注入 Hook 到: %p", target_addr);
        patch_hook_64(target_addr, (void*)my_PacketEncode);
        LOGI("Hook 完成，去游戏中触发发包吧！");

        xdl_close(handle);
    }
}

// --- 保持原版入口，不再变动 ---
std::string GetLibDir(JavaVM *vms) {
    JNIEnv *env = nullptr;
    vms->AttachCurrentThread(&env, nullptr);
    jclass activity_thread_clz = env->FindClass("android/app/ActivityThread");
    if (activity_thread_clz) {
        jmethodID currentApp = env->GetStaticMethodID(activity_thread_clz, "currentApplication", "()Landroid/app/Application;");
        jobject application = env->CallStaticObjectMethod(activity_thread_clz, currentApp);
        jclass app_clazz = env->GetObjectClass(application);
        jmethodID getAppInfo = env->GetMethodID(app_clazz, "getApplicationInfo", "()Landroid/content/pm/ApplicationInfo;");
        jobject app_info = env->CallObjectMethod(application, getAppInfo);
        jfieldID libDirId = env->GetFieldID(env->GetObjectClass(app_info), "nativeLibraryDir", "Ljava/lang/String;");
        auto jstr = (jstring) env->GetObjectField(app_info, libDirId);
        auto path = env->GetStringUTFChars(jstr, nullptr);
        std::string res(path);
        env->ReleaseStringUTFChars(jstr, path);
        return res;
    }
    return {};
}

#if defined(__arm__) || defined(__aarch64__)
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    auto game_data_dir = (const char *) reserved;
    std::thread t(hack_start, game_data_dir);
    t.detach();
    return JNI_VERSION_1_6;
}
#endif
