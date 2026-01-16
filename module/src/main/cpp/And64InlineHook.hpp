#ifndef AND64_INLINE_HOOK_H
#define AND64_INLINE_HOOK_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// 初始化 Hook (传入目标地址，回调函数，和用于保存原函数的指针)
void A64HookFunction(void *const symbol, void *const replace, void **result);

#ifdef __cplusplus
}
#endif

#endif // AND64_INLINE_HOOK_H
