cmake_minimum_required(VERSION 3.18.1)

project("module")

# 设置模块名称，由 gradle 传入
set(MODULE_NAME ${MODULE_NAME})

# 1. 寻找 ShadowHook 路径 (假设在项目根目录或同级)
# 这里指向你之前下载的 shadowhook 文件夹
set(SHADOWHOOK_DIR ${CMAKE_SOURCE_DIR}/../../../../shadowhook)

add_library(${MODULE_NAME} SHARED
    hack.cpp
    # 如果有其他 cpp 文件请加在这里
)

# 2. 包含头文件路径
target_include_directories(${MODULE_NAME} PRIVATE
    ${SHADOWHOOK_DIR}/include
)

# 3. 引用静态库 (静态链接，不再产生 .so 依赖)
add_library(shadowhook_static STATIC IMPORTED)
set_target_properties(shadowhook_static PROPERTIES IMPORTED_LOCATION
    ${SHADOWHOOK_DIR}/libs/${ANDROID_ABI}/libshadowhook.a)

# 4. 链接所有库
target_link_libraries(${MODULE_NAME}
    shadowhook_static
    log
    android
)

# 强制隐藏所有符号以减小体积
set_target_properties(${MODULE_NAME} PROPERTIES
    C_VISIBILITY_PRESET hidden
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
)
