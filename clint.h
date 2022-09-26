#ifndef _CLINT_H_
#define _CLINT_H_

#include "common.h"
#include "trap.h"

#define CLINT_BASE (0x2000000)
#define CLINT_SIZE (0x10000)
#define CLINT_MTIMECMP (CLINT_BASE + 0x4000)
#define CLINT_MTIME (CLINT_BASE + 0xbff8)

struct rv32_clint {
    u32 mtime;
    u32 mtimecmp;
};

struct rv32_clint *clint_init();

exception_t read_clint(struct rv32_clint *clint,
                       u32 addr,
                       u32 size,
                       u32 *result);

exception_t write_clint(struct rv32_clint *clint,
                        u32 addr,
                        u32 size,
                        u32 value);

#endif
