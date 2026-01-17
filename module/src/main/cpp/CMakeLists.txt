cmake_minimum_required(VERSION 3.18.1)
project("module")

set(MODULE_NAME ${MODULE_NAME})

# --- 超强路径搜索逻辑 ---
# 1. 定义搜索起始点（仓库根目录）
get_filename_component(REPO_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../../.." ABSOLUTE)

# 2. 尝试几个常见的大小写组合和路径
set(POSSIBLE_PATHS 
    "${REPO_ROOT}/shadowhook"
    "${REPO_ROOT}/ShadowHook"
    "${CMAKE_CURRENT_SOURCE_DIR}/../../../../shadowhook"
)

set(SHADOWHOOK_DIR "")
foreach(TMP_PATH ${POSSIBLE_PATHS})
    if(EXISTS "${TMP_PATH}/include")
        set(SHADOWHOOK_DIR ${TMP_PATH})
        break()
    endif()
endforeach()

if("${SHADOWHOOK_DIR}" STREQUAL "")
    message(FATAL_ERROR "
    [严重错误] 翻遍了整个仓库都找不到 shadowhook 文件夹！
    请检查：
    1. 你的 GitHub 仓库根目录下是否有 shadowhook 文件夹？
    2. 文件夹里是否有 include 目录？
    当前搜索的根目录是: ${REPO_ROOT}
    ")
endif()
# --- 搜索逻辑结束 ---

add_library(${MODULE_NAME} SHARED hack.cpp)

# 包含头文件
target_include_directories(${MODULE_NAME} PRIVATE ${SHADOWHOOK_DIR}/include)

# 直接定位 .so 文件路径
set(SH_SO_PATH "${SHADOWHOOK_DIR}/libs/arm64-v8a/libshadowhook.so")

if(NOT EXISTS ${SH_SO_PATH})
    message(FATAL_ERROR "找到文件夹但没找到 .so！路径: ${SH_SO_PATH}")
endif()

# 链接
add_library(shadowhook_lib SHARED IMPORTED)
set_target_properties(shadowhook_lib PROPERTIES IMPORTED_LOCATION ${SH_SO_PATH})

target_link_libraries(${MODULE_NAME}
    shadowhook_lib
    log
    android
)
