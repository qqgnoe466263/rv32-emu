#include "cpu.h"

void fetch(rv_cpu *cpu)
{
    cpu->fetch_instr = read_bus(&cpu->bus, cpu->reg.pc, 4);
    PIPE_DBG("[F]    Instr : 0x%08x\n", cpu->fetch_instr);

    if (!cpu->fetch_instr)
        exit(1);
}
