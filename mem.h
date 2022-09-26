#ifndef _MEM_H_
#define _MEM_H_

#include "common.h"
#include "trap.h"

#define RAM_SIZE (1024 * 1024 * 256)
#define RAM_BASE (0x80000000)

#define PAGE_SIZE (4096)

exception_t read_ram(u8 *ram, u32 addr, u32 size, u32 *result);
exception_t write_ram(u8 *ram, u32 addr, u32 size, u32 value);

#endif
