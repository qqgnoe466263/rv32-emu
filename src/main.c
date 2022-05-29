#include <stdio.h>
#include <stdlib.h>

#include "riscv.h"

#if CONFIG_ARCH_TEST
static char signature_out_file[256];
static bool opt_arch_test = false;
#endif

void dump_reg(rv_cpu *cpu)
{
    static char *reg_abi_name[] = {
        "zr", "ra", "sp", "gp", "tp",  "t0",  "t1", "t2", "s0", "s1", "a0",
        "a1", "a2", "a3", "a4", "a5",  "a6",  "a7", "s2", "s3", "s4", "s5",
        "s6", "s7", "s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6"};

    printf("pc = 0x%x\n", cpu->pc);
    for (s8 i = 0; i < 32; i++) {
        printf("x%-2d(%-3s) = 0x%-8x,", i, reg_abi_name[i], cpu->xreg[i]);
        if (!((i + 1) & 3))
            printf("\n");
    }
    printf("\n");
}

/* TODO : PLIC */
static void uart_handler(rv_cpu *cpu)
{
    u8 *uart0_lsr = (u8 *)cpu->bus.vmem.mem + UART0_LSR;
    u8 *uart0_thr = (u8 *)cpu->bus.vmem.mem + UART0_THR;

    if (*uart0_thr) {
        *uart0_lsr &= ~(UART0_LSR_THR_EMPTY | UART0_LSR_THR_SR_EMPTY);
        printf("%c", *uart0_thr);
        *uart0_thr = '\x00';
        *uart0_lsr = (UART0_LSR_THR_EMPTY | UART0_LSR_THR_SR_EMPTY);
    }
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stdout, "Usage : ./rv_emu <ELF format> \n");
        return false;
    }

#if CONFIG_ARCH_TEST
    for (int i = 0; i < argc; i++) {
        if (!strcmp(argv[i], "--arch-test")) {
            opt_arch_test = true;
            strncpy(signature_out_file, argv[i+1], 255);
            signature_out_file[255] = '\0';
            break;
        }
    }
#endif

    rv_emu *emu = init_emu();
    if (!emu)
        return false;

    if (!load_rv_elf(emu, argv[1]))
        goto err;

    while (tick(emu)) {
        /* x0 is always 0 */
        emu->vcpu.xreg[0] = 0;
        /* UART0 Output */
        uart_handler(&emu->vcpu);

        fetch(&emu->vcpu);
        decode(&emu->vcpu);

#if CONFIG_ARCH_TEST
        if (emu->vcpu.decode_instr.type == I_TYPE_SYS)
            if (emu->vcpu.decode_instr.i.func3 == 0x0)
                break;
#endif
        execute(&emu->vcpu);

        if (emu->vcpu.pc_sel)
            emu->vcpu.pc_sel = 0;
        else
            emu->vcpu.pc += 4;
    }

#if CONFIG_ARCH_TEST
    if (opt_arch_test) {
        FILE *f = fopen(signature_out_file, "w");
        if (!f) {
            return -1;
        }
        u32 start = emu->vcpu.bus.vmem.sig.start;
        u32 end   = emu->vcpu.bus.vmem.sig.end;

        for (int i = start; i < end; i += 4) {
            u32 val = read_mem(&emu->vcpu.bus.vmem, i, 4) & 0xffffffff;
            //printf("0x%08x\n", val);
            fprintf(f, "%08x\n", val);
        }
        fclose(f);
    }
#endif

    //dump_reg(&emu->vcpu);

err:
    exit_emu(emu);
    return 0;
}
