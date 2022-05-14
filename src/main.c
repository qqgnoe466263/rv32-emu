#include <stdio.h>
#include <stdlib.h>

#include "riscv.h"

void unit_test_rw_mem_func(rv_emu *emu)
{
    s32 val = 0;
    write_bus(&emu->vcpu.bus, 0x10000001, 0xdeadbeef, 1);
    val = read_bus(&emu->vcpu.bus, 0x10000001, 1);
    printf("[UT] val = 0x%x\n", val);
    write_bus(&emu->vcpu.bus, 0x10000001, 0xdeadbeef, 2);
    val = read_bus(&emu->vcpu.bus, 0x10000001, 2);
    printf("[UT] val = 0x%x\n", val);
    write_bus(&emu->vcpu.bus, 0x10000001, 0xdeadbeef, 4);
    val = read_bus(&emu->vcpu.bus, 0x10000001, 4);
    printf("[UT] val = 0x%x\n", val);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stdout, "Usage : ./rv_emu <ELF format> \n");
        return -1;
    }

    rv_emu *emu = init_emu();
    if (!emu)
        return -1;

#if 1
    unit_test_rw_mem_func(emu);
#endif 

    if (load_rv_elf(emu, argv[1]) < 0)
        return -1;

    exit_emu(emu);

    return 0;
}
