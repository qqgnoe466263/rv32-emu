#include "cpu.h"

void fetch(rv_cpu *cpu)
{
    cpu->fetch_instr = read_bus(&cpu->bus, cpu->pc, 4);
    FETCH_DBG("[F]    PC : 0x%x, Instr : 0x%08x\n",
             cpu->pc, cpu->fetch_instr);
}
