//
// Created by Perfare on 2020/7/4.
//

#ifndef ZYGISK_IL2CPPDUMPER_HACK_H
#define ZYGISK_IL2CPPDUMPER_HACK_H
// 在 hack.h 文件里加入

#include <stddef.h>
// 在 hack.h 文件里加入
void hack_prepare(const char *game_data_dir, void *data, size_t length);

#endif //ZYGISK_IL2CPPDUMPER_HACK_H
