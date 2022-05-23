#include "riscv.h"
#include "elf.h"

rv_emu *init_emu()
{
    rv_emu *emu = malloc(sizeof(rv_emu));
    if (!emu)
        return NULL;

    emu->vcpu.bus.vmem.mem = (u8 *)malloc(MEM_SIZE);
    if (!emu->vcpu.bus.vmem.mem)
        return NULL;

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
