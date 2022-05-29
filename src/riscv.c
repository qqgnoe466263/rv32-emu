#include "riscv.h"
#include "elf.h"
#include "uart.h"
#include "bus.h"

rv_emu *init_emu()
{
    rv_emu *emu = malloc(sizeof(rv_emu));
    if (!emu)
        return NULL;

    emu->vcpu.bus.vmem.mem = (u8 *)malloc(MEM_SIZE);
    if (!emu->vcpu.bus.vmem.mem)
        return NULL;

    /* Init UART0 */
    write_mem(&emu->vcpu.bus.vmem, UART0_LSR,
             (UART0_LSR_THR_EMPTY | UART0_LSR_THR_SR_EMPTY), 4);

    return emu;
}

void exit_emu(rv_emu *emu)
{
    free(emu->vcpu.bus.vmem.mem);
    free(emu);
}

s8 load_rv_elf(rv_emu *emu, u8 *filename)
{
    FILE *f = fopen(filename, "rb");
    if (!f)
        return false;

    fseek(f, 0, SEEK_END);
    size_t fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (!fsize) {
        fclose(f);
        return false;
    }

    u8 *buf = malloc(fsize);
    size_t r = fread(buf, 1, fsize, f);
    //size_t r = fread(emu->vcpu.bus.vmem.mem, 1, fsize, f);
    fclose(f);
    if (r != fsize) {
        free(buf);
        return false;
    }

    if (!parse_elf(&emu->vcpu.bus.vmem, buf, &emu->vcpu.pc)) {
        free(buf);
        return false;
    }

    free(buf);
    return true;
}

void dump_csr(rv_emu *emu)
{
    printf("%-10s = 0x%-8x, \n", "MSTATUS", emu->vcpu.csr[MSTATUS]);
    printf("%-10s = 0x%-8x, \n", "MSTVEC", emu->vcpu.csr[MTVEC]);
    printf("%-10s = 0x%-8x, \n", "MEPC", emu->vcpu.csr[MEPC]);
    printf("%-10s = 0x%-8x, \n", "MCAUSE", emu->vcpu.csr[MCAUSE]);
    printf("%-10s = 0x%-8x, \n", "MIE", emu->vcpu.csr[MIE]);
}

static int cycle = 0;
s8 tick(rv_emu *emu)
{
    if (cycle++ < 15)
        return 1;

    u32 *mtime = (u32 *)(emu->vcpu.bus.vmem.mem + CLINT_MTIME);
    u32 *mtimecmp = (u32 *)(emu->vcpu.bus.vmem.mem + CLINT_MTIMECMP);

    emu->vcpu.csr[TIME]++;
    *mtime = *mtime + 1;
    cycle = 0;

    if (*mtimecmp != 0 && *mtime >= *mtimecmp) {
        emu->vcpu.csr[MIP] |= MIP_MTIP;
        /* Workaround for fixing the repeat timer interrupt */
        *mtime = *mtime - (10000000 / 10000); // about 20m sec in qemu;
    }

    u32 pending = emu->vcpu.csr[MIE] & emu->vcpu.csr[MIP];

    if (pending & MIP_MTIP) {
        if (emu->vcpu.csr[MSTATUS] & MSTATUS_MIE) {
            emu->vcpu.csr[MEPC] = emu->vcpu.pc;
            emu->vcpu.pc = emu->vcpu.csr[MTVEC];
            emu->vcpu.csr[MCAUSE] = (0x80000007);
            emu->vcpu.csr[MSTATUS] &= ~MSTATUS_MIE;

            emu->vcpu.csr[MIP] &= ~MIP_MTIP;
        }
    }

    return true;
}
