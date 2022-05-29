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

#define MEM_SIZE        (0x100000000)

/* CLINT */
#define CLINT_BASE      (0x02000000)
#define CLINT_MTIMECMP  (CLINT_BASE + 0x4000 + 4*(0)) // Hartid
#define CLINT_MTIME 	(CLINT_BASE + 0xBFF8) // cycles since boot.

/* UART */
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
