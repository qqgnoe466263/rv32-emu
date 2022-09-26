#ifndef _PLIC_H_
#define _PLIC_H_

#include "common.h"
#include "trap.h"

#define PLIC_BASE (0xc000000)
#define PLIC_SIZE (0x4000000)
#define PLIC_PENDING (PLIC_BASE + 0x1000)  // Start of pending array (read-only)
#define PLIC_ENABLE (PLIC_BASE + 0x2080)   // Target 1 enables
#define PLIC_PRIORITY (PLIC_BASE + 0x201000)  // Target 1 priority threshold
#define PLIC_CLAIM (PLIC_BASE + 0x201004)     // Target 1 claim/complete

struct rv32_plic {
    u32 pending;
    u32 enable;
    u32 priority;
    u32 claim;
};

struct rv32_plic *plic_init();

exception_t read_plic(struct rv32_plic *plic, u32 addr, u32 size, u32 *result);
exception_t write_plic(struct rv32_plic *plic, u32 addr, u32 size, u32 value);

#endif
