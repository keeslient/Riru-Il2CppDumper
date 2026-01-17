cmake_minimum_required(VERSION 3.18.1)
project("module")

set(MODULE_NAME ${MODULE_NAME})

# 因为 shadowhook 就在当前 CMakeLists.txt 所在的目录下
set(SHADOWHOOK_DIR "${CMAKE_CURRENT_SOURCE_DIR}/shadowhook")

add_library(${MODULE_NAME} SHARED hack.cpp)

# 包含头文件
target_include_directories(${MODULE_NAME} PRIVATE "${SHADOWHOOK_DIR}/include")

# 定位 .so 文件
set(SH_SO_PATH "${SHADOWHOOK_DIR}/libs/arm64-v8a/libshadowhook.so")

if(NOT EXISTS ${SH_SO_PATH})
    message(FATAL_ERROR "！！！在 ${SH_SO_PATH} 找不到文件，请核对你的 shadowhook 文件夹名的大小写 ！！！")
endif()

# 链接依赖
add_library(shadowhook_lib SHARED IMPORTED)
set_target_properties(shadowhook_lib PROPERTIES IMPORTED_LOCATION ${SH_SO_PATH})

target_link_libraries(${MODULE_NAME}
    shadowhook_lib
    log
    android
)
