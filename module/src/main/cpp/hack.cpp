#include <jni.h>
#include <android/log.h>
#include <dlfcn.h>
#include <unistd.h>
#include <string>
#include <cstring>
#include "xdl.h"

// --- 日志定义：你可以直接用 adb logcat -s Perfare_Packet:V 查看 ---
#define LOG_TAG "Perfare_Packet"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// 定义 ShadowHook 初始化函数的函数指针类型
typedef int (*sh_init_t)(int mode);

// 核心入口函数
void hack_start(const char *game_data_dir) {
    LOGI("============================================");
    LOGI("Zygisk-Il2CppDumper 插件已载入！");

    /**
     * 1. 【核心修复】手动加载依赖库
     * 因为 Zygisk 内存加载机制限制，Linker 找不到同级 so。
     * 我们直接去 Magisk 模块的物理安装路径强制把 libshadowhook.so 拽起来。
     * 注意：这里的 il2cpp_dumper 必须和你 gradle 里的 magiskModuleId 一致。
     **/
    const char* sh_path = "/data/adb/modules/il2cpp_dumper/system/lib64/libshadowhook.so";
    
    void* handle = dlopen(sh_path, RTLD_NOW);
    if (!handle) {
        LOGE("手动加载路径失败，尝试直接 dlopen: %s", dlerror());
        handle = dlopen("libshadowhook.so", RTLD_NOW);
    }

    if (handle) {
        sh_init_t shadowhook_init_ptr = (sh_init_t)dlsym(handle, "shadowhook_init");
        if (shadowhook_init_ptr) {
            shadowhook_init_ptr(0); // 初始化 ShadowHook
            LOGI("ShadowHook 环境初始化成功！");
        }
    } else {
        LOGE("致命错误：无法载入 ShadowHook 依赖库，Hook 将无法工作！");
    }

    /**
     * 2. 等待游戏环境解密
     * 很多手游（带 LIAPP 等）在启动初期会扫描内存或解密。
     * 延迟 45 秒可以等游戏完全进入主界面，避开最严密的检查。
     **/
    LOGI("进入 45 秒环境稳定等待期...");
    sleep(45); 

    /**
     * 3. 寻找 libil2cpp.so
     * 这里使用 xdl (项目自带) 进行增强搜索，它比普通的 dlopen 更强。
     **/
    LOGI("开始搜寻游戏核心库 libil2cpp.so...");
    void *il2cpp_handle = xdl_open("libil2cpp.so", XDL_DEFAULT);
    
    if (il2cpp_handle) {
        LOGI("！！！成功抓到 libil2cpp.so ！！！");
        LOGI("现在的内存地址在: %p", il2cpp_handle);
        // 这里下方可以放置你原本的 Dumper 或 Hook 代码
        
        xdl_close(il2cpp_handle);
    } else {
        LOGE("未搜寻到 libil2cpp.so，请确认游戏是否已经完全运行并进入登录界面。");
    }
}

// 兼容 Zygisk 接口的初始化
extern "C" {
    void riru_init(void *arg) {}
}
