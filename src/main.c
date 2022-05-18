#include <stdio.h>
#include <stdlib.h>

#include "riscv.h"

void unit_test_rw_mem_func(rv_emu *emu)
{
    s32 val = 0;
    u32 test_addr = 0x10000001;

    write_bus(&emu->vcpu.bus, test_addr, 0xdeadbeef, 1);
    val = read_bus(&emu->vcpu.bus, test_addr, 1);
    printf("[UT] val = 0x%x\n", val);
    write_bus(&emu->vcpu.bus, test_addr, 0xdeadbeef, 2);
    val = read_bus(&emu->vcpu.bus, test_addr, 2);
    printf("[UT] val = 0x%x\n", val);
    write_bus(&emu->vcpu.bus, test_addr, 0xdeadbeef, 4);
    val = read_bus(&emu->vcpu.bus, test_addr, 4);
    printf("[UT] val = 0x%x\n", val);
}

void dump_reg(rv_cpu *cpu)
{
    static char *reg_abi_name[] = {
        "zr", "ra", "sp", "gp", "tp",  "t0",  "t1", "t2", "s0", "s1", "a0",
        "a1", "a2", "a3", "a4", "a5",  "a6",  "a7", "s2", "s3", "s4", "s5",
        "s6", "s7", "s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6"};

    printf("pc = 0x%x\n", cpu->reg.pc);
    for (s8 i = 0; i < 32; i++) {
        printf("x%-2d(%-3s) = 0x%-8x,", i, reg_abi_name[i], cpu->reg.xreg[i]);
        if (!((i + 1) & 3))
            printf("\n");
    }
    printf("\n");
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

#if 0
    unit_test_rw_mem_func(emu);
#endif

    if (load_rv_elf(emu, argv[1]) < 0)
        goto err;

    while (1) {
        /* x0 is always 0 */
        emu->vcpu.reg.xreg[0] = 0;

        fetch(&emu->vcpu);
#if 1
        if (!emu->vcpu.fetch_instr)
            break;
#endif
        decode(&emu->vcpu);
        execute(&emu->vcpu);

        if (emu->vcpu.pc_sel)
            emu->vcpu.pc_sel = 0;
        else
            emu->vcpu.reg.pc += 4;
    }

    dump_reg(&emu->vcpu);

err:
    exit_emu(emu);
    return 0;
}
