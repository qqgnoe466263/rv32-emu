#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "elf.h"

#define RAM_SIZE (1024 * 1024 * 128)
#define RAM_BASE (0x80000000)

#define RANGE_CHECK(x, minx, size) \
    ((int) ((x - minx) | (minx + size - 1 - x)) >= 0)

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
    OK = -1,
    INSTRUCTION_ACCESS_FAULT = 1,
    ILLEGAL_INSTRUCTION = 2,
    LOAD_ACCESS_FAULT = 5,
    STORE_AMO_ACCESS_FAULT = 7,  // Atomic Memory Operation
} exception_t;

#define UART_BASE (0x10000000)
#define UART_SIZE (0x100)
#define UART_THR (UART_BASE + 0)  // TX
#define UART_RHR (UART_BASE + 0)  // RX
#define UART_LSR (UART_BASE + 5)
#define UART_LSR_RX_EMPTY (1 << 0)
#define UART_LSR_TX_EMPTY (1 << 5)
#define UART_LSR_THR_SR_EMPTY (1 << 6)

struct rv32_uart {
    u8 data[UART_SIZE];
    bool interrupting;

    pthread_t tid;
    pthread_mutex_t lock;
    pthread_cond_t cond;
};

struct rv32_bus {
    u8 *ram;
    struct rv32_uart *uart0;

#if CONFIG_ARCH_TEST
    struct rv32_sig sig;
#endif
};

struct rv32_ctx {
    u32 instr;
};

struct rv32_core {
    u32 xreg[32];
    u32 csr[4096];
    u32 pc;

    struct rv32_bus *bus;

    /* Runtime Context */
    struct rv32_ctx ctx;
};

void pr_err(const char *msg)
{
    fprintf(stderr, "[!] Failed to %s\n", msg);
    exit(1);
}

exception_t read_uart(struct rv32_uart *uart, u32 addr, u32 size, u32 *result)
{
    if (size != 8)
        return LOAD_ACCESS_FAULT;

    pthread_mutex_lock(&uart->lock);
    switch (addr) {
    case UART_RHR:
        pthread_cond_broadcast(&uart->cond);  // wake up thread
        uart->data[UART_LSR - UART_BASE] &= ~UART_LSR_RX_EMPTY;
    default:
        *result = uart->data[addr - UART_BASE];
    }
    pthread_mutex_unlock(&uart->lock);

    return OK;
}

exception_t write_uart(struct rv32_uart *uart, u32 addr, u32 size, u32 value)
{
    if (size != 8)
        return STORE_AMO_ACCESS_FAULT;

    pthread_mutex_lock(&uart->lock);
    switch (addr) {
    case UART_THR:
        fprintf(stdout, "%c", (value & 0xff));
        break;
    default:
        uart->data[addr - UART_BASE] = (value & 0xff);
    }
    pthread_mutex_unlock(&uart->lock);

    return OK;
}

exception_t read_ram(u8 *ram, u32 addr, u32 size, u32 *result)
{
    u32 idx = (addr - RAM_BASE), tmp = 0;

    switch (size) {
    case 32:
        tmp |= (u32)(ram[idx + 3]) << 24;
        tmp |= (u32)(ram[idx + 2]) << 16;
    case 16:
        tmp |= (u32)(ram[idx + 1]) << 8;
    case 8:
        tmp |= (u32)(ram[idx + 0]) << 0;
        *result = tmp;
        return OK;
    default:
        return LOAD_ACCESS_FAULT;
    }
}

exception_t write_ram(u8 *ram, u32 addr, u32 size, u32 value)
{
    u32 idx = (addr - RAM_BASE);

    switch (size) {
    case 32:
        ram[idx + 3] = (value >> 24) & 0xff;
        ram[idx + 2] = (value >> 16) & 0xff;
    case 16:
        ram[idx + 1] = (value >> 8) & 0xff;
    case 8:
        ram[idx + 0] = (value >> 0) & 0xff;
        return OK;
    default:
        return STORE_AMO_ACCESS_FAULT;
    }
}

exception_t read_bus(struct rv32_bus *bus, u32 addr, u32 size, u32 *result)
{
    /* UART RX */
    if (RANGE_CHECK(addr, UART_BASE, UART_SIZE))
        return read_uart(bus->uart0, addr, size, result);
    if (RAM_BASE <= addr)
        return read_ram(bus->ram, addr, size, result);

    return LOAD_ACCESS_FAULT;
}

exception_t write_bus(struct rv32_bus *bus, u32 addr, u32 size, u32 value)
{
    /* UART TX */
    if (RANGE_CHECK(addr, UART_BASE, UART_SIZE))
        return write_uart(bus->uart0, addr, size, value);
    if (RAM_BASE <= addr)
        return write_ram(bus->ram, addr, size, value);

    return STORE_AMO_ACCESS_FAULT;
}

void *uart_thread_func(void *priv)
{
    struct rv32_uart *uart = (struct rv32_uart *) priv;

    /* TODO: UART RX */
    while (1) {
        pthread_mutex_lock(&uart->lock);

        pthread_mutex_unlock(&uart->lock);
    }

    return NULL;
}

struct rv32_uart *uart_init()
{
    struct rv32_uart *uart = malloc(sizeof(struct rv32_uart));

    uart->data[UART_LSR - UART_BASE] |=
        (UART_LSR_TX_EMPTY | UART_LSR_THR_SR_EMPTY);
    pthread_mutex_init(&uart->lock, NULL);
    pthread_cond_init(&uart->cond, NULL);
    pthread_create(&uart->tid, NULL, uart_thread_func, (void *) uart);

    return uart;
}

struct rv32_bus *bus_init()
{
    struct rv32_bus *bus = malloc(sizeof(struct rv32_bus));

    bus->ram = malloc(sizeof(char) * RAM_SIZE);

    return bus;
}

struct rv32_core *core_init()
{
    struct rv32_core *core = malloc(sizeof(struct rv32_core));

    core->bus = bus_init();
    core->bus->uart0 = uart_init();

    /* Initialize the SP(x2) */
    core->xreg[2] = RAM_BASE + RAM_SIZE;

    return core;
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

exception_t fetch(struct rv32_core *core)
{
    core->xreg[0] = 0;

    if (read_bus(core->bus, core->pc, 32, &core->ctx.instr) != OK)
        return INSTRUCTION_ACCESS_FAULT;

    return OK;
}

typedef enum {
    I_TYPE_LOAD = 0b00000011,
    I_TYPE_FENCE = 0b00001111,
    I_TYPE = 0b00010011,
    U_TYPE_AUIPC = 0b00010111,
    S_TYPE = 0b00100011,
#if CONFIG_RV32A_EXTENSION
    A_TYPE = 0b00101111,
#endif
    R_TYPE = 0b00110011,
    U_TYPE_LUI = 0b00110111,
    B_TYPE = 0b01100011,
    I_TYPE_JARL = 0b01100111,
    J_TYPE = 0b01101111,
    I_TYPE_SYS = 0b01110011,
} op_type;

exception_t execute(struct rv32_core *core)
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
            if ((e = read_bus(core->bus, addr, 8, &result)) != OK)
                return e;
            core->xreg[rd] = (s8) result;
            break;
        case 0x1: /* lh */
            if ((e = read_bus(core->bus, addr, 16, &result)) != OK)
                return e;
            core->xreg[rd] = (s16) result;
            break;
        case 0x2: /* lw */
            if ((e = read_bus(core->bus, addr, 32, &result)) != OK)
                return e;
            core->xreg[rd] = (s32) result;
            break;
        case 0x4: /* lbu */
            if ((e = read_bus(core->bus, addr, 8, &core->xreg[rd])) != OK)
                return e;
            break;
        case 0x5: /* lhu */
            if ((e = read_bus(core->bus, addr, 16, &core->xreg[rd])) != OK)
                return e;
            break;
        case 0x6: /* lwu */
            if ((e = read_bus(core->bus, addr, 32, &core->xreg[rd])) != OK)
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
            if ((e = write_bus(core->bus, addr, 8, core->xreg[rs2])) != OK)
                return e;
            break;
        case 0x1: /* sh */
            if ((e = write_bus(core->bus, addr, 16, core->xreg[rs2])) != OK)
                return e;
            break;
        case 0x2: /* sw */
            if ((e = write_bus(core->bus, addr, 32, core->xreg[rs2])) != OK)
                return e;
            break;
        default:
            return ILLEGAL_INSTRUCTION;
        }
        break;
    }
    case A_TYPE: {
        /* TODO */
        switch (func3) {
        default:
            return ILLEGAL_INSTRUCTION;
        }
        break;
    };
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
            if (rs2 == 0x0 && func7 == 0x0) {
                return 0;
            }
        }
        break;
    }
    default:
        return ILLEGAL_INSTRUCTION;
    };

    return OK;
}

int emu(int argc, char **argv)
{
    struct rv32_core *core;
    exception_t e;

    core = core_init();
    core->pc = load_elf(core->bus, argv[1]);

    while (1) {
        if ((e = fetch(core)) != OK) {
            break;
        }

        core->pc += 4;

        if ((e = execute(core)) != OK) {
            break;
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
    if (argc < 2) {
        printf("Usage: %s <filename>\n", argv[0]);
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
