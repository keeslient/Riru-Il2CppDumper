cmake_minimum_required(VERSION 3.18.1)
project("il2cppdumper")

set(MODULE_NAME "il2cppdumper")

# 1. 定义 ShadowHook 和 XDL 的确切位置
set(SH_DIR "${CMAKE_CURRENT_SOURCE_DIR}/shadowhook")
set(XDL_DIR "${CMAKE_CURRENT_SOURCE_DIR}/xdl")

# 2. 编译插件本体
# 直接根据你提供的路径：xdl/xdl.c
add_library(${MODULE_NAME} SHARED
    hack.cpp
    "${XDL_DIR}/xdl.c"
)

# 3. 设置头文件路径
target_include_directories(${MODULE_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    "${XDL_DIR}"
    "${SH_DIR}/include"
)

# 4. 导入 ShadowHook 的动态库 (.so)
add_library(shadowhook SHARED IMPORTED)
set_target_properties(shadowhook PROPERTIES IMPORTED_LOCATION
    "${SH_DIR}/libs/arm64-v8a/libshadowhook.so")

# 5. 链接库
target_link_libraries(${MODULE_NAME}
    shadowhook
    log
    android
)

# 6. 隐藏符号以减小体积并提升隐蔽性
set_target_properties(${MODULE_NAME} PROPERTIES
    C_VISIBILITY_PRESET hidden
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
)
