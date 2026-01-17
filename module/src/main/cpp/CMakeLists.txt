cmake_minimum_required(VERSION 3.18.1)
project("il2cppdumper")

set(MODULE_NAME "il2cppdumper")

# 1. 定义路径
set(SH_DIR "${CMAKE_CURRENT_SOURCE_DIR}/shadowhook")
set(XDL_DIR "${CMAKE_CURRENT_SOURCE_DIR}/xdl")

# 2. 自动搜索 xdl 目录下所有的 .c 文件 (这能解决 undefined symbol 问题)
file(GLOB XDL_SOURCES "${XDL_DIR}/*.c")

# 3. 编译插件本体
add_library(${MODULE_NAME} SHARED
    hack.cpp
    ${XDL_SOURCES}
)

# 4. 设置头文件路径
target_include_directories(${MODULE_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    "${XDL_DIR}"
    "${SH_DIR}/include"
)

# 5. 导入 ShadowHook 库
add_library(shadowhook SHARED IMPORTED)
set_target_properties(shadowhook PROPERTIES IMPORTED_LOCATION
    "${SH_DIR}/libs/arm64-v8a/libshadowhook.so")

# 6. 链接
target_link_libraries(${MODULE_NAME}
    shadowhook
    log
    android
)

# 隐藏符号，减小体积
set_target_properties(${MODULE_NAME} PROPERTIES
    C_VISIBILITY_PRESET hidden
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
)
