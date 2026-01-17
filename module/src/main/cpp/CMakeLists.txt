cmake_minimum_required(VERSION 3.18.1)
project("il2cppdumper")

set(MODULE_NAME "il2cppdumper")

# 1. 设置 ShadowHook 和 XDL 的目录（它们都在当前目录下）
set(SH_DIR "${CMAKE_CURRENT_SOURCE_DIR}/shadowhook")
set(XDL_DIR "${CMAKE_CURRENT_SOURCE_DIR}/xdl")

# 2. 直接编译所有源码
# 我们把 hack.cpp 和 xdl 的核心源码直接打在一起，绕开 add_subdirectory 的坑
add_library(${MODULE_NAME} SHARED
    hack.cpp
    "${XDL_DIR}/src/xdl.c"
)

# 3. 设置头文件路径
target_include_directories(${MODULE_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    "${XDL_DIR}/include"
    "${SH_DIR}/include"
)

# 4. 导入 ShadowHook 库
add_library(shadowhook SHARED IMPORTED)
set_target_properties(shadowhook PROPERTIES IMPORTED_LOCATION
    "${SH_DIR}/libs/arm64-v8a/libshadowhook.so")

# 5. 链接库
target_link_libraries(${MODULE_NAME}
    shadowhook
    log
    android
)

# 6. 隐藏符号并优化
set_target_properties(${MODULE_NAME} PROPERTIES
    C_VISIBILITY_PRESET hidden
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
)
