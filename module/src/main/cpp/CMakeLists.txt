cmake_minimum_required(VERSION 3.18.1)
project("il2cppdumper")

set(MODULE_NAME "il2cppdumper")

# 1. 包含原有的 xdl 源码目录
add_subdirectory(xdl)

# 2. 设置 ShadowHook 路径 (根据你确认的目录结构)
set(SH_DIR "${CMAKE_CURRENT_SOURCE_DIR}/shadowhook")

add_library(${MODULE_NAME} SHARED hack.cpp)

# 3. 设置头文件搜索路径 (包含原有目录和 shadowhook 目录)
target_include_directories(${MODULE_NAME} PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/xdl/include
    ${SH_DIR}/include
)

# 4. 导入 ShadowHook 动态库
add_library(shadowhook_lib SHARED IMPORTED)
set_target_properties(shadowhook_lib PROPERTIES IMPORTED_LOCATION 
    "${SH_DIR}/libs/arm64-v8a/libshadowhook.so")

# 5. 链接所有库 (xdl 是原项目定义的 target)
target_link_libraries(${MODULE_NAME}
    xdl
    shadowhook_lib
    log
    android
)

set_target_properties(${MODULE_NAME} PROPERTIES
    C_VISIBILITY_PRESET hidden
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
)
