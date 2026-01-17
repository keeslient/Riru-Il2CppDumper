cmake_minimum_required(VERSION 3.18.1)
project("module")

set(MODULE_NAME ${MODULE_NAME})

# --- 自动路径探测开始 ---
# 尝试在不同层级寻找 shadowhook 文件夹
set(TRY_PATH_1 "${CMAKE_CURRENT_SOURCE_DIR}/../../../../shadowhook")
set(TRY_PATH_2 "${CMAKE_CURRENT_SOURCE_DIR}/../../../shadowhook")
set(TRY_PATH_3 "${CMAKE_CURRENT_SOURCE_DIR}/../../shadowhook")

if(EXISTS "${TRY_PATH_1}/include")
    set(SHADOWHOOK_DIR ${TRY_PATH_1})
elseif(EXISTS "${TRY_PATH_2}/include")
    set(SHADOWHOOK_DIR ${TRY_PATH_2})
elseif(EXISTS "${TRY_PATH_3}/include")
    set(SHADOWHOOK_DIR ${TRY_PATH_3})
else()
    message(FATAL_ERROR "！！！在源码目录的上层找不到 shadowhook 文件夹，请确认它已上传到 GitHub ！！！")
endif()
# --- 自动路径探测结束 ---

add_library(${MODULE_NAME} SHARED hack.cpp)

# 包含头文件
target_include_directories(${MODULE_NAME} PRIVATE ${SHADOWHOOK_DIR}/include)

# 强制指定 .so 路径，不再用 find_library 这种随缘的方法
set(SH_SO_PATH "${SHADOWHOOK_DIR}/libs/${ANDROID_ABI}/libshadowhook.so")

if(NOT EXISTS ${SH_SO_PATH})
    message(FATAL_ERROR "找到文件夹但没找到 .so 文件！ 预期路径: ${SH_SO_PATH}")
endif()

# 定义并链接动态库
add_library(shadowhook_lib SHARED IMPORTED)
set_target_properties(shadowhook_lib PROPERTIES IMPORTED_LOCATION ${SH_SO_PATH})

target_link_libraries(${MODULE_NAME}
    shadowhook_lib
    log
    android
)
