#ifndef _CPU_H_
#define _CPU_H_

#include "common.h"
#include "bus.h"

typedef struct riscv_register rv_reg;
typedef struct riscv_cpu rv_cpu;

struct riscv_register {
    u32 xreg[32];
    u32 pc;
};

struct riscv_cpu {
    rv_reg reg;
    rv_bus bus;
};

void fetch(rv_cpu *cpu);


#endif
