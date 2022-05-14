#ifndef _RISCV_H_
#define _RISCV_H_

#include "common.h"
#include "mem.h"
#include "cpu.h"

typedef struct riscv_emu rv_emu;

struct riscv_emu {
    rv_cpu vcpu;
};

rv_emu *init_emu();
void exit_emu(rv_emu *emu);

s8 load_rv_elf(rv_emu *emu, u8 *filename);


#endif
