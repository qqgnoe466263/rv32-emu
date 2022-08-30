#ifndef _BOOT_H_
#define _BOOT_H_

#include "common.h"

#define BOOT_ROM_BASE 0x1000

struct rv32_boot {
    u8 *mem;
    size_t size;
};

bool boot_init(struct rv32_boot *boot, u32 entry_addr, char *dtb);

#endif
