#ifndef _BOOT_H_
#define _BOOT_H_

#include "common.h"
#include "trap.h"

#define BOOT_ROM_BASE 0x1000

struct rv32_boot {
    u8 *mem;
    size_t size;
};

bool boot_init(struct rv32_boot *boot, u32 entry_addr, char *dtb);

exception_t read_boot(u8 *ram, u32 addr, u32 size, u32 *result);

#endif
