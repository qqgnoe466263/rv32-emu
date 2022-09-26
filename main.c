#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "boot.h"
#include "bus.h"
#include "clint.h"
#include "elf.h"
#include "plic.h"
#include "trap.h"
#include "uart.h"
#include "virtio.h"

#if CONFIG_ARCH_TEST
static char signature_out_file[256];
static bool opt_arch_test = false;

/* For riscv-test */
struct rv32_sig {
    u32 start;
    u32 end;
};
#endif

typedef enum {
    ACCESS_INSTR,
    ACCESS_LOAD,
    ACCESS_STORE,
} access_t;

/* M mode CSRs */
enum {
    MSTATUS = 0x300,
    MISA = 0x301,
    MEDELEG = 0x302,  // Machine Exception DELEGation
    MIDELEG,          // Machine Interrupt DELEGation
    MIE,              // Machine Interrupt Enable
    MTVEC = 0x305,
    MEPC = 0x341,
    MCAUSE,
    MTVAL,
    MIP,  // Machine Interrupt Pending
    TIME = 0xc01,
};

/* MSTATUS */
enum {
    MSTATUS_MIE = 0x8,    // 1:Enable, 0:Disable
    MSTATUS_MPIE = 0x80,  // Save Previous MSTATUS_MIE value
    MSTATUS_MPP = 0x1800,
};

/* SSTATUS */
enum {
    SSTATUS_SIE = 0x2,
    SSTATUS_SPIE = 0x20,
    SSTATUS_SPP = 0x100,
    SSTATUS_FS = 0x6000,
    SSTATUS_XS = 0x18000,
    SSTATUS_SUM = 0x40000,
    SSTATUS_MXR = 0x80000,
    SSTATUS_UXL = 0x300000000,
};
#define SSTATUS_VISIBLE                                                   \
    (SSTATUS_SIE | SSTATUS_SPIE | SSTATUS_SPP | SSTATUS_FS | SSTATUS_XS | \
     SSTATUS_SUM | SSTATUS_MXR | SSTATUS_UXL)

/* S mode CSRs */
enum {
    SSTATUS = 0x100,
    SEDELEG = 0x102,
    SIDELEG = 0x103,
    SIE = 0x104,
    STVEC,
    SEPC = 0x141,
    SCAUSE,
    STVAL,
    SIP,
    SATP = 0x180,
};

/* MIE */
enum {
    MIE_MSIE = (1 << 3),   // software
    MIE_MTIE = (1 << 7),   // timer
    MIE_MEIE = (1 << 11),  // external
};

/* MIP */
enum {
    MIP_SSIP = (1 << 1),
    MIP_STIP = (1 << 5),
    MIP_SEIP = (1 << 9),
    MIP_MSIP = (1 << 3),
    MIP_MTIP = (1 << 7),
    MIP_MEIP = (1 << 11),
};

/* SIP */
enum {
    SIP_USIP = 0x1,
    SIP_SSIP = 0x2,
    SIP_UEIP = 0x100,
};
#define SIP_WRITABLE (SIP_SSIP | SIP_USIP | SIP_UEIP)

#define MIDELEG_WRITABLE (MIP_SSIP | MIP_STIP | MIP_SEIP)

#define set_csr_bits(core, csr, mask) \
    write_csr(core, csr, read_csr(core, csr) | mask)

#define clear_csr_bits(core, csr, mask) \
    write_csr(core, csr, read_csr(core, csr) & ~mask)

typedef enum {
    USER = 0x0,
    SUPERVISOR = 0x1,
    MACHINE = 0x3,
} core_mode_t;

struct rv32_ctx {
    u32 instr;
    u32 rsvd;
    u8 encode;  // 0: 32bits, 1: 16bits
    u32 stval;
};

struct rv32_core {
    core_mode_t mode;
    u32 xreg[32];
    u32 csr[4096];
    u32 pc;

    struct rv32_bus *bus;
    bool enable_paging;
    u32 pagetable;

    /* Runtime Context */
    struct rv32_ctx ctx;
};

bool exception_is_fatal(exception_t e)
{
    switch (e) {
    case INSTRUCTION_ADDRESS_MISALIGNED:
    case INSTRUCTION_ACCESS_FAULT:
    case LOAD_ACCESS_FAULT:
    case STORE_AMO_ADDRESS_MISALIGNED:
    case STORE_AMO_ACCESS_FAULT:
        return true;
    default:
        return false;
    }
}

u32 read_csr(struct rv32_core *core, u16 addr)
{
    switch (addr) {
    case SSTATUS:
        return (core->csr[MSTATUS] & SSTATUS_VISIBLE);
    case SIE:
        return (core->csr[MIE] & core->csr[MIDELEG]);
    case SIP:
        return (core->csr[MIP] & core->csr[MIDELEG]);
    default:
        return core->csr[addr];
    }
}

void write_csr(struct rv32_core *core, u16 addr, u32 value)
{
    switch (addr) {
    case SSTATUS: {
        u32 *mstatus = &core->csr[MSTATUS];
        *mstatus = (*mstatus & ~SSTATUS_VISIBLE) | (value & SSTATUS_VISIBLE);
        break;
    }
    case SIE: {
        u32 *mie = &core->csr[MIE];
        u32 mask = core->csr[MIDELEG];
        *mie = (*mie & ~mask) | (value & mask);
        break;
    }
    case SIP: {
        u32 *mip = &core->csr[MIP];
        u32 mask = core->csr[MIDELEG] & SIP_WRITABLE;
        *mip = (*mip & ~mask) | (value & mask);
        break;
    }
    case MIDELEG: {
        u32 *mideleg = &core->csr[MIDELEG];
        *mideleg = (*mideleg & ~MIDELEG_WRITABLE) | (value & MIDELEG_WRITABLE);
        break;
    }
    default:
        core->csr[addr] = value;
    }
}

exception_t mmu_translate(struct rv32_core *core,
                          u32 addr,
                          exception_t e,
                          u32 *result,
                          access_t access)
{
    if (!core->enable_paging) {
        *result = addr;
        return OK;
    }

    if (core->mode == MACHINE) {
        if ((access == ACCESS_INSTR) || !(read_csr(core, MSTATUS) & 0x20000)) {
            *result = addr;
            return OK;
        }
    }

    u32 vpn[] = {
        (addr >> 12) & 0x3ff,  // 10bits
        (addr >> 22) & 0x3ff,  // 10bits
    };
    int level = sizeof(vpn) / sizeof(vpn[0]) - 1;
    u32 pt = core->pagetable;
    u32 pte;

#define PTE_SIZE 4

    bool v, r, w, x;
    while (1) {
        exception_t except =
            read_bus(core->bus, pt + vpn[level] * PTE_SIZE, 32, &pte);

        if (except != OK)
            return except;

        v = pte & 1;
        r = (pte >> 1) & 0x1;
        w = (pte >> 2) & 0x1;
        x = (pte >> 3) & 0x1;

        if (!v || (!r && w))
            goto fail;

        if (r || x)
            break;

        /* 10bits of flags */
        pt = ((pte >> 10) & 0x0fffffff) * PAGE_SIZE;
        if (--level < 0)
            goto fail;
    }

    switch (access) {
    case ACCESS_INSTR:
        if (x == 0)
            goto fail;
        break;
    case ACCESS_LOAD:
        if (r == 0)
            goto fail;
        break;
    case ACCESS_STORE:
        if (w == 0)
            goto fail;
        break;
    }

    u32 ppn[] = {
        (pte >> 10) & 0xfff,  // 12bits
        (pte >> 20) & 0xfff,  // 12bits
    };

    switch (level) {
    case 0:
        *result = (ppn[1] << 22) | (ppn[0] << 12) | (addr & 0xfff);
        return OK;
    case 1:
        *result = (ppn[1] << 22) | (addr & 0x3fffff);
        return OK;
    }

fail:

    core->ctx.stval = addr;

    switch (access) {
    case ACCESS_INSTR:
        return INSTRUCTION_PAGE_FAULT;
    case ACCESS_LOAD:
        return LOAD_PAGE_FAULT;
    case ACCESS_STORE:
        return STORE_PAGE_FAULT;
    }

    /* Never come to here */
    return OK;
}

exception_t core_read_bus(struct rv32_core *core,
                          u32 addr,
                          u32 size,
                          u32 *result)
{
    u32 pa;
    exception_t e =
        mmu_translate(core, addr, LOAD_PAGE_FAULT, &pa, ACCESS_LOAD);
    if (e != OK)
        return e;

    return read_bus(core->bus, pa, size, result);
}

exception_t core_write_bus(struct rv32_core *core,
                           u32 addr,
                           u32 size,
                           u32 value)
{
    u32 pa;
    exception_t e =
        mmu_translate(core, addr, LOAD_PAGE_FAULT, &pa, ACCESS_STORE);
    if (e != OK)
        return e;

    return write_bus(core->bus, pa, size, value);
}

void load_binary(struct rv32_bus *bus, char *filename, u32 offset)
{
    FILE *f = fopen(filename, "rb");
    if (!f) {
        printf("Open %s Failed!\n", filename);
        goto out;
    }

    fseek(f, 0, SEEK_END);
    size_t fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (fread(bus->ram + offset, fsize, 1, f) != 1) {
        printf("Read %s Failed!\n", filename);
        goto out;
    }

    fclose(f);
    return;
out:
    exit(0);
}

u32 load_elf(struct rv32_bus *bus, char *filename)
{
    FILE *f = fopen(filename, "rb");
    if (!f)
        pr_err("Open Kernel ELF File !");

    fseek(f, 0, SEEK_END);
    size_t fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    u8 *buf = malloc(sizeof(char) * fsize);
    if (fread(buf, fsize, 1, f) != 1)
        pr_err("Read Kernel ELF File !");

    fclose(f);

#if CONFIG_ARCH_TEST
    u32 pc = parse_elf(bus->ram, buf, &bus->sig.start, &bus->sig.end);
#else
    u32 pc = parse_elf(bus->ram, buf);
#endif

    free(buf);
    return pc;
}

u8 *load_disk(char *filename)
{
    FILE *f = fopen(filename, "rb");
    if (!f)
        pr_err("Open Disk IMG !");

    fseek(f, 0, SEEK_END);
    size_t fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    u8 *disk = malloc(sizeof(char) * fsize);
    if (fread(disk, fsize, 1, f) != 1)
        pr_err("Read Disk IMG !");
    fclose(f);

    return disk;
}

void csr_init(struct rv32_core *core)
{
    memset(&core->csr, '\x00', sizeof(u32) * 4096);

    u32 misa = (1 << 30) |  // RV32
               (1 << 0) |   // ATOMIC extension
               (1 << 2) |   // Compressed extension
               (1 << 8) |   // RV32I/64I/128I base ISA
               (1 << 12) |  // Integer Multiply/Divide extension
               (1 << 18) |  // Supervisor mode implemented
               (1 << 20);   // User mode implemented

    write_csr(core, MISA, misa);
}

int parse_arg(char *arg, int argc, char **argv)
{
    for (int i = 0; i < argc; i++) {
        if (!strncmp(arg, argv[i], strlen(arg)))
            return i + 1;
    }

    return -1;
}

struct rv32_core *core_init(int argc, char **argv)
{
    struct rv32_core *core = malloc(sizeof(struct rv32_core));

    core->bus = bus_init();
    core->mode = MACHINE;

#ifdef CONFIG_ARCH_TEST
    load_elf(core->bus, argv[1]);
    core->pc = RAM_BASE;
#else
    int opt_idx = 0;
    char *bios_f = NULL;
    char *kernel_f = NULL;
    char *elf_f = NULL;
    char *rootfs_f = NULL;
    char *dtb = NULL;

    opt_idx = parse_arg("--bios", argc, argv);
    if (opt_idx != -1)
        bios_f = argv[opt_idx];

    opt_idx = parse_arg("--kernel", argc, argv);
    if (opt_idx != -1)
        kernel_f = argv[opt_idx];

    opt_idx = parse_arg("--elf", argc, argv);
    if (opt_idx != -1)
        elf_f = argv[opt_idx];

    opt_idx = parse_arg("--rootfs", argc, argv);
    if (opt_idx != -1)
        rootfs_f = argv[opt_idx];

    opt_idx = parse_arg("--dtb", argc, argv);
    if (opt_idx != -1)
        dtb = argv[opt_idx];

    if (bios_f) {
        load_binary(core->bus, bios_f, 0x0);
        core->pc = BOOT_ROM_BASE;
    }

    if (kernel_f) {
        // load_binary(core->bus, kernel_f, 0x04000000);
        load_binary(core->bus, kernel_f, 0x00400000);
    }

    if (elf_f) {
        load_elf(core->bus, elf_f);
        core->pc = RAM_BASE;
    }

    if (rootfs_f) {
        core->bus->virtio = virtio_init(load_disk(rootfs_f));
    }

    if (!boot_init(core->bus->boot, RAM_BASE, dtb))
        exit(0);
#endif

    /* Initialize the SP(x2) */
    core->xreg[2] = RAM_BASE + RAM_SIZE;
    csr_init(core);

    return core;
}

exception_t fetch(struct rv32_core *core)
{
    u32 ppc;
    u32 encode;

    exception_t e = mmu_translate(core, core->pc, INSTRUCTION_PAGE_FAULT, &ppc,
                                  ACCESS_INSTR);

    if (e != OK)
        return e;

    core->xreg[0] = 0;

    if (read_bus(core->bus, ppc, 8, &encode) != OK)
        return INSTRUCTION_ACCESS_FAULT;

    if ((encode & 0x3) == 0x3) {
        core->ctx.encode = 0;
        if (read_bus(core->bus, ppc, 32, &core->ctx.instr) != OK)
            return INSTRUCTION_ACCESS_FAULT;
    } else {
        core->ctx.encode = 1;
        if (read_bus(core->bus, ppc, 16, &core->ctx.instr) != OK)
            return INSTRUCTION_ACCESS_FAULT;
    }

    return OK;
}

#define SATP_SV32 (1 << 31)
void core_update_paging(struct rv32_core *core, u16 csr_addr)
{
    if (csr_addr != SATP)
        return;

    /* rv32 : ppn is 22bits
     * rv64 : ppn is 44bits
     */
    core->pagetable =
        (read_csr(core, SATP) & (((u32) 1 << 22) - 1)) * PAGE_SIZE;
    core->enable_paging = (1 == (read_csr(core, SATP) >> 31));
}

typedef enum {
    I_TYPE_LOAD = 0b00000011,
    I_TYPE_FENCE = 0b00001111,
    I_TYPE = 0b00010011,
    U_TYPE_AUIPC = 0b00010111,
    S_TYPE = 0b00100011,
    A_TYPE = 0b00101111,
    R_TYPE = 0b00110011,
    U_TYPE_LUI = 0b00110111,
    B_TYPE = 0b01100011,
    I_TYPE_JARL = 0b01100111,
    J_TYPE = 0b01101111,
    I_TYPE_SYS = 0b01110011,
} op_type;

exception_t execute_32(struct rv32_core *core)
{
    u32 instr = core->ctx.instr;
    u32 opcode = instr & 0x7f;
    u32 rd = (instr >> 7) & 0x1f;
    u32 rs1 = (instr >> 15) & 0x1f;
    u32 rs2 = (instr >> 20) & 0x1f;
    u32 func3 = (instr >> 12) & 0x7;
    u32 func7 = (instr >> 25) & 0x7f;

    exception_t e;

    switch (opcode) {
    case I_TYPE_LOAD: {
        u32 imm = (int) instr >> 20;
        u32 addr = core->xreg[rs1] + imm;
        u32 result = 0;
        switch (func3) {
        case 0x0: /* lb */
            if ((e = core_read_bus(core, addr, 8, &result)) != OK)
                return e;
            core->xreg[rd] = (s8) result;
            break;
        case 0x1: /* lh */
            if ((e = core_read_bus(core, addr, 16, &result)) != OK)
                return e;
            core->xreg[rd] = (s16) result;
            break;
        case 0x2: /* lw */
            if ((e = core_read_bus(core, addr, 32, &result)) != OK)
                return e;
            core->xreg[rd] = (s32) result;
            break;
        case 0x4: /* lbu */
            if ((e = core_read_bus(core, addr, 8, &core->xreg[rd])) != OK)
                return e;
            break;
        case 0x5: /* lhu */
            if ((e = core_read_bus(core, addr, 16, &core->xreg[rd])) != OK)
                return e;
            break;
        case 0x6: /* lwu */
            if ((e = core_read_bus(core, addr, 32, &core->xreg[rd])) != OK)
                return e;
            break;
        default:
            return ILLEGAL_INSTRUCTION;
        }
        break;
    }
    case I_TYPE_FENCE:
        switch (func3) {
        case 0x0: /* fence */
            /* TODO */
            break;
        case 0x1: /* fence.i */
            /* TODO */
            break;
        default:
            return ILLEGAL_INSTRUCTION;
        }
    case I_TYPE: {
        u32 imm = (int) (instr & 0xfff00000) >> 20;
        u32 shamt = imm & 0x3f;  // imm[0:4]
        switch (func3) {
        case 0x0: /* addi */
            core->xreg[rd] = core->xreg[rs1] + imm;
            break;
        case 0x1: /* slli */
            core->xreg[rd] = core->xreg[rs1] << shamt;
            break;
        case 0x2: /* slti */
            core->xreg[rd] = ((s32) core->xreg[rs1] < (s32) imm) ? 1 : 0;
            break;
        case 0x3: /* sltiu */
            core->xreg[rd] = (core->xreg[rs1] < imm) ? 1 : 0;
            break;
        case 0x4: /* xori */
            core->xreg[rd] = core->xreg[rs1] ^ imm;
            break;
        case 0x5:
            switch (func7) {
            case 0x0: /* srli */
                core->xreg[rd] = core->xreg[rs1] >> shamt;
                break;
            case 0x20: /* srai */
                core->xreg[rd] = (s32) core->xreg[rs1] >> shamt;
                break;
            default:
                return ILLEGAL_INSTRUCTION;
            }
            break;
        case 0x6: /* ori */
            core->xreg[rd] = core->xreg[rs1] | imm;
            break;
        case 0x7: /* andi */
            core->xreg[rd] = core->xreg[rs1] & imm;
            break;
        default:
            return ILLEGAL_INSTRUCTION;
        }
        break;
    }
    case U_TYPE_AUIPC: { /* auipc */
        u32 imm = (s32)(instr & 0xfffff000);
        core->xreg[rd] = core->pc + imm - 4;
        break;
    }
    case S_TYPE: {
        u32 imm =
            (u32)((s32)(instr & 0xfe000000) >> 20) | ((instr >> 7) & 0x1f);
        u32 addr = core->xreg[rs1] + imm;
        switch (func3) {
        case 0x0: /* sb */
            if ((e = core_write_bus(core, addr, 8, core->xreg[rs2])) != OK)
                return e;
            break;
        case 0x1: /* sh */
            if ((e = core_write_bus(core, addr, 16, core->xreg[rs2])) != OK)
                return e;
            break;
        case 0x2: /* sw */
            if ((e = core_write_bus(core, addr, 32, core->xreg[rs2])) != OK)
                return e;
            break;
        default:
            return ILLEGAL_INSTRUCTION;
        }
        break;
    }
    case A_TYPE: {
        u32 func5 = (func7 & 0x7c) >> 2;
        if (func3 == 0x2 && func5 == 0x0) { /* amoadd.w */
            u32 tmp = 0;
            if ((e = core_read_bus(core, core->xreg[rs1], 32, &tmp)) != OK)
                return e;
            if ((e = core_write_bus(core, core->xreg[rs1], 32,
                                    tmp + core->xreg[rs2])) != OK)
                return e;
            core->xreg[rd] = (int) tmp;
        } else if (func3 == 0x2 && func5 == 0x1) { /* amoswap.w */
            u32 tmp = 0;
            if ((e = core_read_bus(core, core->xreg[rs1], 32, &tmp)) != OK)
                return e;
            if ((e = core_write_bus(core, core->xreg[rs1], 32,
                                    core->xreg[rs2])) != OK)
                return e;
            core->xreg[rd] = (int) tmp;
        } else if (func3 == 0x2 && func5 == 0x2) { /* lr.w */
            u32 addr = core->xreg[rs1];
            u32 tmp = 0;
            if ((e = core_read_bus(core, addr, 32, &tmp) != OK))
                return e;
            core->xreg[rd] = (s32)(tmp & 0xffffffff);
            core->ctx.rsvd = addr;
        } else if (func3 == 0x2 && func5 == 0x3) { /* sc.w */
            u32 addr = core->xreg[rs1];
            if (core->ctx.rsvd == addr) {
                if ((e = core_write_bus(core, addr, 32, core->xreg[rs2])) != OK)
                    return e;
                core->xreg[rd] = 0;
            } else {
                core->xreg[rd] = 1;
            }
            core->ctx.rsvd = (u32) -1;
        } else if (func3 == 0x2 && func5 == 0xC) { /* amoand.w */
            u32 addr = core->xreg[rs1];
            u32 tmp = 0;
            if ((e = core_read_bus(core, addr, 32, &tmp)) != OK)
                return e;
            u32 value = (int) ((tmp & core->xreg[rs2]) & 0xffffffff);
            if ((e = core_write_bus(core, addr, 32, value)) != OK)
                return e;
            core->xreg[rd] = (int) (tmp & 0xffffffff);
        } else if (func3 == 0x2 && func5 == 0x8) { /* amoor.w */
            u32 addr = core->xreg[rs1];
            u32 tmp = 0;
            if ((e = core_read_bus(core, addr, 32, &tmp)) != OK)
                return e;
            u32 value = (int) ((tmp | core->xreg[rs2]) & 0xffffffff);
            if ((e = core_write_bus(core, addr, 32, value)) != OK)
                return e;
            core->xreg[rd] = (int) (tmp & 0xffffffff);
        } else {
            return ILLEGAL_INSTRUCTION;
        }
        break;
    }
    case R_TYPE: {
        u32 shamt = core->xreg[rs2] & 0x3f;
        if (func3 == 0x0 && func7 == 0x00) { /* add */
            core->xreg[rd] = core->xreg[rs1] + core->xreg[rs2];
        } else if (func3 == 0x0 && func7 == 0x01) { /* mul */
            core->xreg[rd] = (s32) core->xreg[rs1] * (s32) core->xreg[rs2];
        } else if (func3 == 0x0 && func7 == 0x20) { /* sub */
            core->xreg[rd] = core->xreg[rs1] - core->xreg[rs2];
        } else if (func3 == 0x1 && func7 == 0x00) { /* sll */
            core->xreg[rd] = core->xreg[rs1] << shamt;
        } else if (func3 == 0x1 && func7 == 0x01) { /* mulh */
            long tmp =
                (long) (s32) core->xreg[rs1] * (long) (s32) core->xreg[rs2];
            core->xreg[rd] = tmp >> 32;
        } else if (func3 == 0x2 && func7 == 0x00) { /* slt */
            core->xreg[rd] =
                ((s32) core->xreg[rs1] < (s32) core->xreg[rs2]) ? 1 : 0;
        } else if (func3 == 0x2 && func7 == 0x01) { /* mulhsu */
            long tmp =
                (long) (s32) core->xreg[rs1] * (unsigned long) core->xreg[rs2];
            core->xreg[rd] = tmp >> 32;
        } else if (func3 == 0x3 && func7 == 0x00) { /* sltu */
            core->xreg[rd] = !!(core->xreg[rs1] < core->xreg[rs2]);
        } else if (func3 == 0x3 && func7 == 0x01) { /* mulhu */
            unsigned long tmp = (unsigned long) core->xreg[rs1] *
                                (unsigned long) core->xreg[rs2];
            core->xreg[rd] = tmp >> 32;
        } else if (func3 == 0x4 && func7 == 0x00) { /* xor */
            core->xreg[rd] = core->xreg[rs1] ^ core->xreg[rs2];
        } else if (func3 == 0x4 && func7 == 0x01) { /* div */
            s32 dividend = (s32) core->xreg[rs1];
            s32 divisor = (s32) core->xreg[rs2];
            if (!divisor)
                core->xreg[rd] = -1;
            else
                core->xreg[rd] = dividend / divisor;
        } else if (func3 == 0x5 && func7 == 0x00) { /* srl */
            core->xreg[rd] = core->xreg[rs1] >> shamt;
        } else if (func3 == 0x5 && func7 == 0x01) { /* divu */
            u32 dividend = core->xreg[rs1];
            u32 divisor = core->xreg[rs2];
            if (!divisor)
                core->xreg[rd] = -1;
            else
                core->xreg[rd] = dividend / divisor;
        } else if (func3 == 0x5 && func7 == 0x20) { /* sra */
            core->xreg[rd] = (s32) core->xreg[rs1] >> shamt;
        } else if (func3 == 0x6 && func7 == 0x00) { /* or */
            core->xreg[rd] = core->xreg[rs1] | core->xreg[rs2];
        } else if (func3 == 0x6 && func7 == 0x01) { /* rem */
            core->xreg[rd] = (s32) core->xreg[rs1] % (s32) core->xreg[rs2];
        } else if (func3 == 0x7 && func7 == 0x00) { /* and */
            core->xreg[rd] = core->xreg[rs1] & core->xreg[rs2];
        } else if (func3 == 0x7 && func7 == 0x01) { /* remu */
            core->xreg[rd] = core->xreg[rs1] % core->xreg[rs2];
        } else {
            return ILLEGAL_INSTRUCTION;
        }
        break;
    }
    case U_TYPE_LUI: /* lui */
        core->xreg[rd] = (s32)(instr & 0xfffff000);
        break;
    case B_TYPE: {
        u32 imm = (u32)((s32)(instr & 0x80000000) >> 19) |
                  ((instr & 0x80) << 4) | ((instr >> 20) & 0x7e0) |
                  ((instr >> 7) & 0x1e);
        switch (func3) {
        case 0x0: /* beq */
            if (core->xreg[rs1] == core->xreg[rs2])
                core->pc += imm - 4;
            break;
        case 0x1: /* bne */
            if (core->xreg[rs1] != core->xreg[rs2])
                core->pc += imm - 4;
            break;
        case 0x4: /* blt */
            if ((s32) core->xreg[rs1] < (s32) core->xreg[rs2])
                core->pc += imm - 4;
            break;
        case 0x5: /* bge */
            if ((s32) core->xreg[rs1] >= (s32) core->xreg[rs2])
                core->pc += imm - 4;
            break;
        case 0x6: /* bltu */
            if (core->xreg[rs1] < core->xreg[rs2])
                core->pc += imm - 4;
            break;
        case 0x7: /* bgeu */
            if (core->xreg[rs1] >= core->xreg[rs2])
                core->pc += imm - 4;
            break;
        default:
            return ILLEGAL_INSTRUCTION;
        }
        break;
    }
    case I_TYPE_JARL: { /* jalr */
        u32 tmp = core->pc;
        u32 imm = (s32)(instr & 0xfff00000) >> 20;
        core->pc = (core->xreg[rs1] + imm) & ~1;
        core->xreg[rd] = tmp;
        break;
    }
    case J_TYPE: { /* jal */
        core->xreg[rd] = core->pc;
        u32 imm = (u32)((s32)(instr & 0x80000000) >> 11) | (instr & 0xff000) |
                  ((instr >> 9) & 0x800) | ((instr >> 20) & 0x7fe);
        core->pc += imm - 4;
        break;
    }
    case I_TYPE_SYS: {
        u16 addr = (instr & 0xfff00000) >> 20;
        switch (func3) {
        case 0x0:
            if (rs2 == 0x0 && func7 == 0x0) { /* ecall */
                switch (core->mode) {
                case USER:
                case SUPERVISOR:
                case MACHINE:
                    return 8 + core->mode;
                }
            } else if (rs2 == 0x1 && func7 == 0x0) { /* ebreak */
                return BREAKPOINT;
            } else if (rs2 == 0x2 && func7 == 0x8) { /* sret */
                core->pc = read_csr(core, SEPC);
                core->mode = read_csr(core, SSTATUS) >> 8;
                write_csr(core, SSTATUS,
                          ((read_csr(core, SSTATUS) >> 5) & 1)
                              ? read_csr(core, SSTATUS) | (1 << 1)
                              : read_csr(core, SSTATUS) & ~(1 << 1));
                write_csr(core, SSTATUS, read_csr(core, SSTATUS) | (1 << 5));
                write_csr(core, SSTATUS, read_csr(core, SSTATUS) & ~(1 << 8));
            } else if (rs2 == 0x2 && func7 == 0x18) { /* mret */
                printf("mret\n");
                core->pc = read_csr(core, MEPC);
                core->mode = (read_csr(core, MSTATUS) >> 11) & 3;
                write_csr(core, MSTATUS,
                          ((read_csr(core, MSTATUS) >> 7) & 1)
                              ? read_csr(core, MSTATUS) | (MSTATUS_MIE)
                              : read_csr(core, MSTATUS) & ~(MSTATUS_MIE));
                write_csr(core, MSTATUS,
                          read_csr(core, MSTATUS) | (MSTATUS_MPIE));
                write_csr(core, MSTATUS, read_csr(core, MSTATUS) & ~(3 << 11));
            } else { /* sfence.vma */
                // printf("sfence.vma, 0x%x\n", core->pc);
            }
            break;
        case 0x1: { /* csrrw */
            u32 tmp = read_csr(core, addr);
            write_csr(core, addr, core->xreg[rs1]);
            core->xreg[rd] = tmp;
            core_update_paging(core, addr);
            break;
        }
        case 0x2: { /* csrrs */
            u32 tmp = read_csr(core, addr);
            write_csr(core, addr, tmp | core->xreg[rs1]);
            core->xreg[rd] = tmp;
            core_update_paging(core, addr);
            break;
        }
        case 0x3: { /* csrrc */
            u32 tmp = read_csr(core, addr);
            write_csr(core, addr, tmp & ~core->xreg[rs1]);
            core->xreg[rd] = tmp;
            core_update_paging(core, addr);
            break;
        }
        case 0x5: { /* csrrwi */
            core->xreg[rd] = read_csr(core, addr);
            write_csr(core, addr, rs1);
            core_update_paging(core, addr);
            break;
        }
        case 0x6: { /* csrrsi */
            u32 tmp = read_csr(core, addr);
            write_csr(core, addr, tmp | rs1);
            core->xreg[rd] = tmp;
            core_update_paging(core, addr);
            break;
        }
        case 0x7: { /* csrrci */
            u32 tmp = read_csr(core, addr);
            write_csr(core, addr, tmp & ~rs1);
            core->xreg[rd] = tmp;
            core_update_paging(core, addr);
            break;
        }
        default:
            return ILLEGAL_INSTRUCTION;
        }
        break;
    }
    default:
        return ILLEGAL_INSTRUCTION;
    };

    return OK;
}
exception_t execute_16(struct rv32_core *core)
{
    u16 instr = (u16) core->ctx.instr;
    u8 opcode = instr & 0x3;
    u8 func3 = (instr >> 13) & 0x7;
    u8 func4 = (instr >> 12) & 0xf;
    u8 func6 = (instr >> 10) & 0x3f;
    u8 func8 = (func6 << 2) | ((instr >> 5) & 0x3);

    exception_t e;

    switch (opcode) {
    case 0x0: {
        u32 result = 0;
        u32 addr = 0;
        u8 offset = 0;
        u8 rd_ = ((instr >> 2) & 0x7) + 8;   // dest
        u8 rs2_ = ((instr >> 2) & 0x7) + 8;  // src
        u8 rs1_ = ((instr >> 7) & 0x7) + 8;  // base

        switch (func3) {
        case 0x0: { /* c.addi4spn */
            u32 imm = ((instr >> 5) & 0x1) << 3 | ((instr >> 6) & 0x1) << 2 |
                      ((instr >> 7) & 0xf) << 6 | ((instr >> 11) & 0x3) << 4;
            if (imm != 0)
                core->xreg[rd_] = core->xreg[2] + imm;
        } break;
        case 0x2: /* c.lw */
            offset = ((instr >> 5) & 0x1) << 6 | ((instr >> 6) & 0x1) << 2 |
                     ((instr >> 10) & 0x7) << 3;
            addr = core->xreg[rs1_] + offset;

            if ((e = core_read_bus(core, addr, 32, &result)) != OK)
                return e;
            core->xreg[rd_] = (s32) result;
            break;
        case 0x6: /* c.sw */
            offset = ((instr >> 5) & 0x1) << 6 | ((instr >> 6) & 0x1) << 2 |
                     ((instr >> 10) & 0x7) << 3;
            addr = core->xreg[rs1_] + offset;

            if ((e = core_write_bus(core, addr, 32, core->xreg[rs2_])) != OK)
                return e;

            break;
        default:
            return ILLEGAL_INSTRUCTION;
        }
    } break;
    case 0x1: {
        u8 rs2_ = ((instr >> 2) & 0x7) + 8;  // src
        u8 rs1_ = ((instr >> 7) & 0x7) + 8;  // dest
        u8 rd_ = ((instr >> 7) & 0x7) + 8;   // dest
        u8 rd = ((instr >> 7) & 0x1f);       // dest
        u8 func2 = (instr >> 10) & 0x3;
        u32 shamt = ((instr >> 12) & 0x1) << 5 | ((instr >> 2) & 0x1f);

        if (func3 == 0x4 && func2 == 0x0) { /* c.srli */
            core->xreg[rd_] >>= shamt;
        } else if (func3 == 0x4 && func2 == 0x1) { /* c.srai */
            core->xreg[rd_] = (s32) core->xreg[rd_] >> shamt;
        } else if (func3 == 0x0 && rd != 0) { /* c.addi */
            s32 imm = ((instr >> 12) & 0x1) << 5 | ((instr >> 2) & 0x1f);
            // sign-extended 6-bit immediate
            imm |= (imm & 0x20) ? 0xffffffc0 : 0;
            if (imm != 0)
                core->xreg[rd] = (u32)((s32) core->xreg[rd] + imm);
        } else if (func3 == 0x4 && func2 == 0x2) { /* c.andi */
            s32 imm = ((instr >> 12) & 0x1) << 5 | ((instr >> 2) & 0x1f);
            // sign-extended 6-bit immediate
            imm |= (imm & 0x20) ? 0xffffffc0 : 0;
            core->xreg[rd_] = (s32) core->xreg[rd_] & imm;
        } else if (func3 == 0x3) {
            if (rd != 0 && rd != 2) { /* c.lui */
                s32 imm = ((instr >> 2) & 0x1f) << 12 | ((instr >> 12) & 0x1)
                                                            << 17;
                imm |= (imm & 0x20000) ? 0xffffc0000 : 0;
                core->xreg[rd] = imm;
            } else if (rd == 2) { /* c.addi16sp */
                s32 imm = ((instr >> 12) & 0x1) << 9 |
                          ((instr >> 2) & 0x1) << 5 |
                          ((instr >> 3) & 0x3) << 7 |
                          ((instr >> 5) & 0x1) << 6 | ((instr >> 6) & 0x1) << 4;
                imm |= (imm & 0x200) ? 0xffffffc00 : 0;
                if (imm != 0)
                    core->xreg[2] = (u32)((s32) core->xreg[2] + imm);
            }
        } else if (func3 == 0x5) { /* c.j */
            u32 offset =
                ((instr >> 2) & 0x1) << 5 | ((instr >> 3) & 0x7) << 1 |
                ((instr >> 6) & 0x1) << 7 | ((instr >> 7) & 0x1) << 6 |
                ((instr >> 8) & 0x1) << 10 | ((instr >> 9) & 0x3) << 8 |
                ((instr >> 11) & 0x1) << 4 | ((instr >> 12) & 0x1) << 11;
            offset |= (offset & 0x800) ? 0xfffff000 : 0;
            core->pc += (offset - 2);
        } else if (func3 == 0x1) { /* c.jal */
            u32 offset =
                ((instr >> 2) & 0x1) << 5 | ((instr >> 3) & 0x7) << 1 |
                ((instr >> 6) & 0x1) << 7 | ((instr >> 7) & 0x1) << 6 |
                ((instr >> 8) & 0x1) << 10 | ((instr >> 9) & 0x3) << 8 |
                ((instr >> 11) & 0x1) << 4 | ((instr >> 12) & 0x1) << 11;
            offset |= (offset & 0x800) ? 0xfffff000 : 0;
            core->xreg[1] = core->pc;
            core->pc += (offset - 2);
        } else if (func3 == 0x6) { /* c.beqz */
            u32 offset = ((instr >> 2) & 0x1) << 5 | ((instr >> 3) & 0x3) << 1 |
                         ((instr >> 5) & 0x3) << 6 |
                         ((instr >> 10) & 0x3) << 3 |
                         ((instr >> 12) & 0x1) << 8;
            offset |= (offset & 0x100) ? 0xfffffE00 : 0;
            if (core->xreg[rs1_] == 0)
                core->pc += (offset - 2);
        } else if (func3 == 0x7) { /* c.bnqz */
            u32 offset = ((instr >> 2) & 0x1) << 5 | ((instr >> 3) & 0x3) << 1 |
                         ((instr >> 5) & 0x3) << 6 |
                         ((instr >> 10) & 0x3) << 3 |
                         ((instr >> 12) & 0x1) << 8;
            offset |= (offset & 0x100) ? 0xfffffE00 : 0;
            if (core->xreg[rs1_] != 0)
                core->pc += (offset - 2);
        } else if (func3 == 0x2) { /* c.li */
            s32 imm = ((instr >> 12) & 0x1) << 5 | ((instr >> 2) & 0x1f);
            imm |= (imm & 0x20) ? 0xffffffc0 : 0;
            core->xreg[rd] = imm;
        } else if (func3 == 0x0) { /* c.nop */
            return OK;
        } else {
            switch (func8) {
            case 0x8f: /* c.and */
                core->xreg[rd_] &= core->xreg[rs2_];
                break;
            case 0x8e: /* c.or */
                core->xreg[rd_] |= core->xreg[rs2_];
                break;
            case 0x8d: /* c.xor */
                core->xreg[rd_] ^= core->xreg[rs2_];
                break;
            case 0x8c: /* c.sub */
                core->xreg[rd_] -= core->xreg[rs2_];
                break;

            default:
                return ILLEGAL_INSTRUCTION;
            }
        }

    } break;
    case 0x2: {
        u32 rs2 = ((instr >> 2) & 0x1f);
        u32 rs1 = ((instr >> 7) & 0x1f);
        u32 rd = ((instr >> 7) & 0x1f);
        u32 offset = 0;
        u32 addr = 0;
        u32 shamt = ((instr >> 12) & 0x1) << 5 | ((instr >> 2) & 0x1f);

        if ((func3 == 0x4 && func4 == 0x9) && rs2 != 0) { /* c.add */
            core->xreg[rd] =
                (s32)((u32) core->xreg[rd] + (u32) core->xreg[rs2]);
        } else if (func4 == 0x9 && rs2 == 0) {
            if (rs1 == 0) { /* c.ebreak */
                core->pc += 2;
                return BREAKPOINT;
            } else { /* c.jalr */
                u32 prev_pc = core->pc;
                core->pc = core->xreg[rs1];
                core->xreg[1] = prev_pc;
            }
        } else if (func4 == 0x8 && rs1 != 0 && rs2 == 0) { /* c.jr */
            core->pc = core->xreg[rs1];
        } else if ((func3 == 0x4 && func4 == 0x8) && rs2 != 0) { /* c.mv */
            core->xreg[rd] = core->xreg[rs2];
        } else if (func3 == 0x0) { /* c.slli */
            core->xreg[rd] = core->xreg[rs1] << shamt;
        } else if (func3 == 0x2) { /* c. lwsp */
            offset = ((instr >> 2) & 0x3) << 6 | ((instr >> 4) & 0x7) << 2 |
                     ((instr >> 12) & 0x1) << 5;
            addr = core->xreg[2] + offset;  // sp
            if ((e = core_read_bus(core, addr, 32, &core->xreg[rd])) != OK)
                return e;
        } else if (func3 == 0x6) { /* c.swsp */
            offset = ((instr >> 7) & 0x3) << 6 | ((instr >> 9) & 0xf) << 2;
            addr = core->xreg[2] + offset;  // sp
            if ((e = core_write_bus(core, addr, 32, core->xreg[rs2])) != OK)
                return e;
        } else {
            return ILLEGAL_INSTRUCTION;
        }
    } break;
    default:
        return ILLEGAL_INSTRUCTION;
    };

    return OK;
}

exception_t execute(struct rv32_core *core)
{
    if (!core->ctx.encode) {
        core->pc += 4;
        return execute_32(core);
    } else {
        core->pc += 2;
        return execute_16(core);
    }

    /* never be here */
    return OK;
}


void trap_handler(struct rv32_core *core,
                  const exception_t e,
                  const interrupt_t intr)
{
    core_mode_t prev_mode = core->mode;
    u32 exception_pc;
    bool is_interrupt = (intr != NONE);
    u32 cause = is_interrupt ? intr : e;

    switch (e) {
    case BREAKPOINT:
    case ECALL_FROM_S_MODE:
    case ECALL_FROM_U_MODE:
        exception_pc = core->pc - 4;
        break;
    default:
        exception_pc = core->pc;
    }

    // Delegate to lower privilege mode if needed
    if (is_interrupt) {
        if (((read_csr(core, MIDELEG) >> cause) & 1) == 0)
            core->mode = MACHINE;
        else {
            if (((read_csr(core, SIDELEG) >> cause) & 1) == 0)
                core->mode = SUPERVISOR;
        }

        cause = (0x80000000 | intr);
    } else {
        if (((read_csr(core, MEDELEG) >> cause) & 1) == 0)
            core->mode = MACHINE;
        else {
            if (((read_csr(core, SEDELEG) >> cause) & 1) == 0)
                core->mode = SUPERVISOR;
            else
                core->mode = USER;
        }
    }

    if (core->mode == SUPERVISOR) {
        /* Set PC to handler routine address */
        if (is_interrupt) {
            u32 stvec = read_csr(core, STVEC);
            if (stvec & 0x1)
                core->pc = (stvec & ~0x3) + 4 * cause;
            else
                core->pc = stvec & ~0x3;
        } else
            core->pc = read_csr(core, STVEC) & ~0x3;

        write_csr(core, SEPC, exception_pc & ~1);
        write_csr(core, SCAUSE, cause);
        write_csr(core, STVAL, core->ctx.stval);

        u32 sstatus = read_csr(core, SSTATUS);
        write_csr(core, SSTATUS,
                  (sstatus & ~SSTATUS_SPIE) | ((sstatus & SSTATUS_SIE) << 4));
        clear_csr_bits(core, SSTATUS, SSTATUS_SIE);
        sstatus = read_csr(core, SSTATUS);
        write_csr(core, SSTATUS, (sstatus & ~SSTATUS_SPP) | prev_mode << 8);
    } else if (core->mode == MACHINE) {
        /* Set PC to handler routine address */
        if (is_interrupt) {
            u32 mtvec = read_csr(core, MTVEC);
            if (mtvec & 0x1)
                core->pc = (mtvec & ~0x3) + 4 * cause;
            else
                core->pc = mtvec & ~0x3;
        } else
            core->pc = read_csr(core, MTVEC) & ~0x3;

        /* Store the PC which got the exception to MEPC */
        write_csr(core, MEPC, exception_pc & ~1);

        /* Set the trap reason to MCAUSE */
        write_csr(core, MCAUSE, cause);

        /* Set MTVAL to 0 because this is an interrupt
         * (access illegal and illegal Instruction need to update MTVAL)
         */
        write_csr(core, MTVAL, 0);

        u32 mstatus = read_csr(core, MSTATUS);
        write_csr(core, MSTATUS,
                  (mstatus & ~MSTATUS_MPIE) | ((mstatus & MSTATUS_MIE) << 4));

        clear_csr_bits(core, MSTATUS, MSTATUS_MIE);
        mstatus = read_csr(core, MSTATUS);
        write_csr(core, MSTATUS, (mstatus & ~MSTATUS_MPP) | prev_mode << 11);
    } else if (core->mode == USER) {
        /* TODO */
        printf("User mode trap handler not imp!\n");
        exit(0);
    }
}

enum {
    VIRTIO_IRQ = 1,
    UART_IRQ = 10,
};

interrupt_t check_pending_interrupt(struct rv32_core *core)
{
    /* Check the Interrupt Enable or not.
     * Priority: M > S > U
     */
    if (core->mode == MACHINE && (read_csr(core, MSTATUS & MSTATUS_MIE) == 0))
        return NONE;
    if (core->mode == SUPERVISOR &&
        ((read_csr(core, SSTATUS) & SSTATUS_SIE) == 0))
        return NONE;

    /* Handle External Interrupt */
    do {
        u32 irq;
        if (uart_is_interrupting(core->bus->uart0)) {
            irq = UART_IRQ;
        } else if (virtio_is_interrupting(core->bus->virtio)) {
            printf("virtio interrupt\n");
            bus_disk_access(core->bus);
            irq = VIRTIO_IRQ;
        } else
            break;
        write_bus(core->bus, PLIC_CLAIM, 32, irq);

        if (core->mode == SUPERVISOR)
            write_csr(core, MIP, read_csr(core, MIP) | MIP_SEIP);
        else if (core->mode == MACHINE)
            write_csr(core, MIP, read_csr(core, MIP) | MIP_MEIP);
    } while (0);

    /* When CPU will handle an interrupt?
     * e.g. Machine Timer Interrupt.
     *      mstatus.mie = 1
     *      mie (bit7) = 1
     *      mip (bit7) = 1
     */

    u32 pending = read_csr(core, MIE) & read_csr(core, MIP);

    /* Machine External Interrupt Pending */
    if (pending & MIP_MEIP) {
        write_csr(core, MIP, read_csr(core, MIP) & ~MIP_MEIP);
        return MACHINE_EXTERNAL_INTERRUPT;
    }

    /* Machine Software Interrupt Pending */
    if (pending & MIP_MSIP) {
        write_csr(core, MIP, read_csr(core, MIP) & ~MIP_MSIP);
        return MACHINE_SOFTWARE_INTERRUPT;
    }

    /* Machine Timer Interrupt Pending */
    if (pending & MIP_MTIP) {
        /* Clear Timer Interrupt Pending flag */
        printf("MTIP\n");
        write_csr(core, MIP, read_csr(core, MIP) & ~MIP_MTIP);
        return MACHINE_TIMER_INTERRUPT;
    }

    /* Supervisor External Interrupt Pending */
    if (pending && MIP_SEIP) {
        write_csr(core, MIP, read_csr(core, MIP) & ~MIP_SEIP);
        return SUPERVISOR_EXTERNAL_INTERRUPT;
    }

    /* Supervisor Software Interrupt Pending */
    if (pending & MIP_SSIP) {
        write_csr(core, MIP, read_csr(core, MIP) & ~MIP_SSIP);
        return SUPERVISOR_SOFTWARE_INTERRUPT;
    }

    /* Supervisor Timer Interrupt Pending */
    if (pending & MIP_STIP) {
        write_csr(core, MIP, read_csr(core, MIP) & ~MIP_STIP);
        return SUPERVISOR_TIMER_INTERRUPT;
    }

    return NONE;
}

void tick(struct rv32_core *core)
{
    struct rv32_clint *clint = core->bus->clint;

    clint->mtime++;
    core->csr[TIME] = clint->mtime;

    if ((clint->mtimecmp > 0) & (clint->mtime >= clint->mtimecmp)) {
        write_csr(core, MIP, MIP_MTIP);
        /* TODO: This is a workaround */
        clint->mtimecmp *= 2;
    }
}

int emu(int argc, char **argv)
{
    struct rv32_core *core;
    exception_t e;
    core = core_init(argc, argv);

    while (1) {
        /* FIXME:
         * Tick causes xv6-rv32 booting hanging.
         * Bus now we need this function to boot linux 5.4.
         */
        tick(core);

    re_fetch:
        if ((e = fetch(core)) != OK) {
            trap_handler(core, e, NONE);
            if (e == INSTRUCTION_PAGE_FAULT)
                goto re_fetch;
            if (exception_is_fatal(e))
                break;
        }

        if ((e = execute(core)) != OK) {
            trap_handler(core, e, NONE);
            if (exception_is_fatal(e))
                break;
        }

        interrupt_t intr;
        if ((intr = check_pending_interrupt(core)) != NONE) {
            trap_handler(core, OK, intr);
        }
    }

#if CONFIG_ARCH_TEST
    if (opt_arch_test) {
        FILE *f = fopen(signature_out_file, "w");
        if (!f)
            return 0;

        u32 start = core->bus->sig.start;
        u32 end = core->bus->sig.end;

        for (int i = start; i < end; i += 4) {
            u32 val = 0;
            read_ram(core->bus->ram, i, 32, &val);
            fprintf(f, "%08x\n", (val & 0xffffffff));
        }
        fclose(f);
    }
#endif

    return 0;
}

int main(int argc, char **argv)
{
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    if (argc < 2) {
        printf(
            "Usage: %s --bios [<firmware>]\n"
            "\t\t--kernel [<elf>]\n"
            "\t\t--rootfs [<rootfs>]\n",
            argv[0]);
        return -1;
    }

#if CONFIG_ARCH_TEST
    for (int i = 0; i < argc; i++) {
        if (!strcmp(argv[i], "--arch-test")) {
            opt_arch_test = true;
            strncpy(signature_out_file, argv[i + 1], 255);
            signature_out_file[255] = '\0';
            break;
        }
    }
#endif

    return emu(argc, argv);
}
