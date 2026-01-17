cmake_minimum_required(VERSION 3.18.1)

# 项目名称
project("il2cppdumper")

# 设置模块名称
set(MODULE_NAME "il2cppdumper")

# 1. 定义依赖目录（都在当前目录下）
set(SH_DIR "${CMAKE_CURRENT_SOURCE_DIR}/shadowhook")
set(XDL_DIR "${CMAKE_CURRENT_SOURCE_DIR}/xdl")

# 2. 自动搜索 xdl 目录下所有的 .c 源文件（确保补全所有 xdl 零件）
file(GLOB XDL_SOURCES "${XDL_DIR}/*.c")

# 3. 编译插件本体
# 注意：这里我们只编译源码，不链接外部 .so，防止加载时 Linker 找不到库而卡死
add_library(${MODULE_NAME} SHARED
    hack.cpp
    ${XDL_SOURCES}
)

# 4. 设置头文件搜索路径
target_include_directories(${MODULE_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    "${XDL_DIR}"
    "${SH_DIR}/include"
)

# 5. 链接系统库（仅链接必有的 log 和 android 库）
target_link_libraries(${MODULE_NAME}
    log
    android
)

# 6. 隐藏符号，减小体积，提升隐蔽性
set_target_properties(${MODULE_NAME} PROPERTIES
    C_VISIBILITY_PRESET hidden
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
)
