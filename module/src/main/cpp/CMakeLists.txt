cmake_minimum_required(VERSION 3.18.1)
project("il2cppdumper")

set(MODULE_NAME "il2cppdumper")

# 1. 自动搜索当前目录下 xdl 文件夹里的所有 C 文件
set(XDL_DIR "${CMAKE_CURRENT_SOURCE_DIR}/xdl")
file(GLOB XDL_SOURCES "${XDL_DIR}/*.c")

# 2. 编译插件本体
add_library(${MODULE_NAME} SHARED
    hack.cpp
    ${XDL_SOURCES}
)

# 3. 包含头文件路径
target_include_directories(${MODULE_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    "${XDL_DIR}"
)

# 4. 只链接系统自带的库，不带任何累赘
target_link_libraries(${MODULE_NAME}
    log
    android
)

# 隐藏符号，减小体积
set_target_properties(${MODULE_NAME} PROPERTIES
    C_VISIBILITY_PRESET hidden
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
)
