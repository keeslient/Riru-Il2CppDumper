cmake_minimum_required(VERSION 3.18.1)
project("module")

set(MODULE_NAME ${MODULE_NAME})

# 路径指向你刚才确认的位置
set(SHADOWHOOK_DIR "${CMAKE_CURRENT_SOURCE_DIR}/shadowhook")

add_library(${MODULE_NAME} SHARED hack.cpp)

# 包含头文件目录 (确保 xdl.h 和 shadowhook.h 都在这里)
target_include_directories(${MODULE_NAME} PRIVATE "${SHADOWHOOK_DIR}/include")

# 1. 链接 ShadowHook 库
set(SH_SO_PATH "${SHADOWHOOK_DIR}/libs/arm64-v8a/libshadowhook.so")
add_library(shadowhook_lib SHARED IMPORTED)
set_target_properties(shadowhook_lib PROPERTIES IMPORTED_LOCATION ${SH_SO_PATH})

# 2. 如果你的 libs 里也有 libxdl.so，请取消下面两行的注释（如果没有就保持现状）
# add_library(xdl_lib SHARED IMPORTED)
# set_target_properties(xdl_lib PROPERTIES IMPORTED_LOCATION "${SHADOWHOOK_DIR}/libs/arm64-v8a/libxdl.so")

target_link_libraries(${MODULE_NAME}
    shadowhook_lib
    log
    android
)

# 隐藏符号，减小体积
set_target_properties(${MODULE_NAME} PROPERTIES
    C_VISIBILITY_PRESET hidden
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
)
