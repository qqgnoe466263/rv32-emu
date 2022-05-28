#ifndef _MEM_H_
#define _MEM_H_

#include "common.h"
#include "uart.h"

typedef struct riscv_memory_entry rv_mem_entry;
typedef struct riscv_mem rv_mem;
typedef struct riscv_elf rv_elf;

enum {
    BOOTROM,
    CLINT,
    PLIC,
    UART0,
    VIRTIO,
    KERNBASE,
};

struct riscv_memory_entry {
    u32 base;
    u32 size;
};

static const rv_mem_entry mem_map[] = {
    [BOOTROM]  = {0x00001000, 0xf000},
    [CLINT]    = {0x02000000, 0x10000},
    [PLIC]     = {0x0c000000, 0x10000},
    [UART0]    = {0x10000000, 0x100},
    [VIRTIO]   = {0x10001000, 0x1000},
    [KERNBASE] = {0x80000000, 0x10001000}, /* 256MB */
};

#define MEM_SIZE        (0x100000000)
#define UART0_BASE      (0x10000000)

/* For riscv-compliance */
struct riscv_elf {
    u32 start;
    u32 end;
};

struct riscv_mem {
    u8 *mem;
    rv_elf sig;
};

s32 read_mem(rv_mem *mem, u32 addr, u8 byte);
void write_mem(rv_mem *mem, u32 addr, u32 data, u8 byte);

#endif
