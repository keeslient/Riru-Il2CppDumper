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
# 3. 【汇编指令替换】下载官方 Dobby 并替换非法指令
# ==============================================================================
include(FetchContent)

message(STATUS "Downloading Official Dobby & Patching Assembly...")

# 解释：
# 1. 还是下载官方 master.zip (保证能下载)
# 2. 使用 sed 做高级替换：
#    - 把 'adrp ... @PAGE' 替换成 'ldr x17, =common_closure_bridge_handler' (伪指令，自动处理地址)
#    - 把 'add ... @PAGEOFF' 这一行直接删掉 (因为 ldr 已经把地址拿到了，不需要 add 了)
FetchContent_Declare(
  dobby
  URL https://github.com/jmpews/Dobby/archive/refs/heads/master.zip
  PATCH_COMMAND sed -i -e "s/adrp.*common_closure_bridge_handler@PAGE/ldr x17, =common_closure_bridge_handler/g" -e "/add.*common_closure_bridge_handler@PAGEOFF/d" ${CMAKE_CURRENT_BINARY_DIR}/_deps/dobby-src/source/TrampolineBridge/ClosureTrampolineBridge/arm64/closure_bridge_arm64.asm
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
