cmake_minimum_required(VERSION 3.18.1)

# ==============================================================================
# 1. 保持原有的项目配置逻辑
# ==============================================================================
if (NOT DEFINED MODULE_NAME)
    message(FATAL_ERROR "MODULE_NAME is not set")
else ()
    project(${MODULE_NAME})
endif ()

message("Build type: ${CMAKE_BUILD_TYPE}")

set(CMAKE_CXX_STANDARD 20)

# ==============================================================================
# 2. 保持原有的 Flag 配置
# ==============================================================================
set(LINKER_FLAGS "-ffixed-x18 -Wl,--hash-style=both")
set(C_FLAGS "-Werror=format -fdata-sections -ffunction-sections")
set(CXX_FLAGS "${CXX_FLAGS} -fno-exceptions -fno-rtti")

if (NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(C_FLAGS "${C_FLAGS} -O2 -fvisibility=hidden -fvisibility-inlines-hidden")
    set(LINKER_FLAGS "${LINKER_FLAGS} -Wl,-exclude-libs,ALL -Wl,--gc-sections -Wl,--strip-all")
else ()
    set(C_FLAGS "${C_FLAGS} -O0")
endif ()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${C_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${C_FLAGS} ${CXX_FLAGS}")

set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${LINKER_FLAGS}")
set(CMAKE_MODULE_LINKER_FLAGS "${CMAKE_MODULE_LINKER_FLAGS} ${LINKER_FLAGS}")

# ==============================================================================
# 3. 【绝对稳妥】下载官方源码 + 自动修补汇编错误
# ==============================================================================
include(FetchContent)

message(STATUS "Downloading Official Dobby & Patching for NDK25...")

# 1. 下载官方 master 分支 (100% 存在)
# 2. 使用 PATCH_COMMAND 自动修改 asm 文件，移除 NDK25 不支持的 @PAGE 写法
FetchContent_Declare(
  dobby
  URL https://github.com/jmpews/Dobby/archive/refs/heads/master.zip
  PATCH_COMMAND sed -i "s/@PAGE//g" ${CMAKE_CURRENT_BINARY_DIR}/_deps/dobby-src/source/TrampolineBridge/ClosureTrampolineBridge/arm64/closure_bridge_arm64.asm
)
# 解压并配置
FetchContent_MakeAvailable(dobby)

# ==============================================================================
# 4. 包含路径
# ==============================================================================
include_directories(
        xdl/include
        ${dobby_SOURCE_DIR}/include
)

aux_source_directory(xdl xdl-src)

# ==============================================================================
# 5. 编译目标
# ==============================================================================
add_library(${MODULE_NAME} SHARED
        main.cpp
        hack.cpp
        il2cpp_dump.cpp
        ${xdl-src})

# ==============================================================================
# 6. 链接库
# ==============================================================================
target_link_libraries(${MODULE_NAME} 
        log 
        dobby 
)

# ==============================================================================
# 7. 保持原本的 Strip 逻辑
# ==============================================================================
if (NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_custom_command(TARGET ${MODULE_NAME} POST_BUILD
            COMMAND ${CMAKE_STRIP} --strip-all --remove-section=.comment "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/lib${MODULE_NAME}.so")
endif ()
