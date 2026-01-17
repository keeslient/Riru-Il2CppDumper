cmake_minimum_required(VERSION 3.18.1)
project("il2cppdumper")

set(MODULE_NAME "il2cppdumper")

# 1. 自动搜索 xdl 目录下所有的 .c 源文件（解决 ld error）
set(XDL_DIR "${CMAKE_CURRENT_SOURCE_DIR}/xdl")
file(GLOB XDL_SOURCES "${XDL_DIR}/*.c")

# 2. 编译插件本体
add_library(${MODULE_NAME} SHARED
    hack.cpp
    ${XDL_SOURCES}
)

# 3. 设置头文件路径
target_include_directories(${MODULE_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    "${XDL_DIR}"
    "${CMAKE_CURRENT_SOURCE_DIR}/shadowhook/include"
)

# 4. 【关键】这里只链接系统日志库，不要链接 shadowhook！
# 我们在 hack.cpp 里手动 dlopen 它，防止链接器报错卡死
target_link_libraries(${MODULE_NAME}
    log
    android
)

# 隐藏符号，提升隐蔽性
set_target_properties(${MODULE_NAME} PROPERTIES
    C_VISIBILITY_PRESET hidden
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
)
