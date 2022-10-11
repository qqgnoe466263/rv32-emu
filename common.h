#ifndef _COMMON_H_
#define _COMMON_H_

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned char u8;
typedef signed char s8;
typedef unsigned short u16;
typedef signed short s16;
typedef unsigned int u32;
typedef signed int s32;
typedef unsigned long u64;
typedef signed long s64;

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

static inline void pr_err(const char *msg)
{
    fprintf(stderr, "[!] Failed to %s\n", msg);
    exit(1);
}

#if CONFIG_ARCH_TEST
/* For riscv-test */
struct rv32_sig {
    u32 start;
    u32 end;
};
#endif



#endif
