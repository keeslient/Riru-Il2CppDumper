#include "And64InlineHook.hpp"
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

// 基础宏定义
#define PAGE_START(addr) ((addr) & PAGE_MASK)
#define PAGE_END(addr)   (PAGE_START(addr) + PAGE_SIZE)

// 简单的指令修复逻辑
void A64HookFunction(void *const symbol, void *const replace, void **result) {
    long page_size = sysconf(_SC_PAGESIZE);
    uintptr_t start = (uintptr_t)symbol;
    uintptr_t base = start & ~(page_size - 1);
    
    // 修改内存权限为可写
    mprotect((void *)base, page_size, PROT_READ | PROT_WRITE | PROT_EXEC);

    // 备份原函数的前 16 字节 (4条指令足够了)
    // 注意：这里为了简化，假设原函数开头指令不需要重定位（大部分函数都符合）
    // 如果 result 不为空，我们需要创建一个 Trampoline（跳板）
    if (result != NULL) {
        // 分配一块内存做跳板
        void *trampoline = mmap(NULL, page_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        
        // 1. 复制原函数头部的指令到跳板
        memcpy(trampoline, symbol, 16);
        
        // 2. 在跳板末尾写入跳转回原函数剩余部分的指令
        uint32_t *p = (uint32_t *)((uintptr_t)trampoline + 16);
        uintptr_t return_addr = start + 16;
        
        // LDR x17, #8; BR x17; [address]
        p[0] = 0x58000051; // ldr x17, .+8
        p[1] = 0xd61f0220; // br x17
        *(uintptr_t *)&p[2] = return_addr;
        
        *result = trampoline;
    }

    // 构造跳转指令 (Inline Hook)
    // LDR x17, #8; BR x17; [replace_address]
    uint32_t *target = (uint32_t *)start;
    target[0] = 0x58000051; // ldr x17, .+8
    target[1] = 0xd61f0220; // br x17
    *(uintptr_t *)&target[2] = (uintptr_t)replace;

    // 刷新 CPU 缓存
    __builtin___clear_cache((char *)start, (char *)start + 16);
}
