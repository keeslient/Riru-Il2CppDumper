cmake_minimum_required(VERSION 3.18.1)
project("module")

set(MODULE_NAME ${MODULE_NAME})

# 自动定位项目根目录下的 shadowhook
set(SHADOWHOOK_DIR ${CMAKE_SOURCE_DIR}/../../../../shadowhook)

add_library(${MODULE_NAME} SHARED hack.cpp)

# 包含头文件
target_include_directories(${MODULE_NAME} PRIVATE ${SHADOWHOOK_DIR}/include)

# 查找静态库：先找 libshadowhook_static.a，再找 libshadowhook.a
find_library(SH_LIB
    NAMES shadowhook_static shadowhook
    PATHS ${SHADOWHOOK_DIR}/libs/${ANDROID_ABI}
    NO_DEFAULT_PATH
)

if(NOT SH_LIB)
    message(FATAL_ERROR "！！！未找到静态库文件，请检查 shadowhook/libs/${ANDROID_ABI}/ 下是否存在 .a 文件 ！！！")
endif()

target_link_libraries(${MODULE_NAME}
    ${SH_LIB}
    log
    android
)

# 隐藏符号，减小体积
set_target_properties(${MODULE_NAME} PROPERTIES
    C_VISIBILITY_PRESET hidden
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
)
