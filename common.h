#ifndef _COMMON_H_
#define _COMMON_H_

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CONFIG_RV32M_EXTENSION 1
#define CONFIG_RV32A_EXTENSION 1

typedef unsigned char u8;
typedef signed char s8;
typedef unsigned short u16;
typedef signed short s16;
typedef unsigned int u32;
typedef signed int s32;

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#endif
