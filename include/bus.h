#ifndef _BUS_H_
#define _BUS_H_

#include "common.h"
#include "mem.h"

typedef struct riscv_bus rv_bus;

struct riscv_bus {
    rv_mem vmem;
};

s32 read_bus(rv_bus *bus, u32 addr, u8 byte);
void write_bus(rv_bus *bus, u32 addr, u32 data, u8 byte);

#endif
