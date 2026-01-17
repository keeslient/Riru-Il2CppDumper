cmake_minimum_required(VERSION 3.18.1)
project("module")

set(MODULE_NAME ${MODULE_NAME})

# 1. 设置 ShadowHook 目录路径 (请确保路径正确指向你的 shadowhook 文件夹)
set(SHADOWHOOK_DIR ${CMAKE_SOURCE_DIR}/../../../../shadowhook)

add_library(${MODULE_NAME} SHARED hack.cpp)

# 2. 包含头文件
target_include_directories(${MODULE_NAME} PRIVATE ${SHADOWHOOK_DIR}/include)

# 3. 链接已有的动态库 (.so)
find_library(SH_LIB
    NAMES shadowhook
    PATHS ${SHADOWHOOK_DIR}/libs/${ANDROID_ABI}
    NO_DEFAULT_PATH
)

target_link_libraries(${MODULE_NAME}
    ${SH_LIB}
    log
    android
)
