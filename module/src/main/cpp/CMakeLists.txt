cmake_minimum_required(VERSION 3.18.1)
project("il2cppdumper")

set(MODULE_NAME "il2cppdumper")

# 1. 设置项目自带的 xdl 路径
set(XDL_DIR "${CMAKE_CURRENT_SOURCE_DIR}/xdl")

# 2. 自动包含 xdl 目录下所有的 .c 源文件
file(GLOB XDL_SOURCES "${XDL_DIR}/*.c")

# 3. 编译插件本体
# 注意：我们不链接任何外部 Hook 库，只编译源码
add_library(${MODULE_NAME} SHARED
    hack.cpp
    ${XDL_SOURCES}
)

# 4. 包含头文件路径 (关键修复：xdl 的头文件在 include 文件夹里)
target_include_directories(${MODULE_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    "${XDL_DIR}/include"
)

# 5. 只链接系统日志库，不产生任何 .so 依赖，彻底防止加载卡死
target_link_libraries(${MODULE_NAME}
    log
    android
)

# 6. 符号隐藏优化
set_target_properties(${MODULE_NAME} PROPERTIES
    C_VISIBILITY_PRESET hidden
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
)
