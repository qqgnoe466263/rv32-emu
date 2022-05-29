#ifndef _CPU_H_
#define _CPU_H_

#include "common.h"
#include "bus.h"
#include "csr.h"

typedef struct riscv_register       rv_reg;
typedef struct riscv_cpu            rv_cpu;
typedef struct riscv_instruction    rv_instr;

enum {
    I_TYPE_LOAD  = 0b00000011,
    I_TYPE_FENCE = 0b00001111,
    I_TYPE       = 0b00010011,
    U_TYPE_AUIPC = 0b00010111,
    S_TYPE       = 0b00100011,
#if CONFIG_RV32A_EXTENSION
    RV32A_TYPE   = 0b00101111,
#endif
    R_TYPE       = 0b00110011,
    U_TYPE_LUI   = 0b00110111,
    B_TYPE       = 0b01100011,
    I_TYPE_JARL  = 0b01100111,
    J_TYPE       = 0b01101111,
    I_TYPE_SYS   = 0b01110011,
} op_type;

typedef struct riscv_instruction {
    u8 type; // opcode
    union {
        struct {
            u32 op:7;
            u32 rd:5;
            u32 func3:3;
            u32 rs1:5;
            u32 imm:12;
        } i;

        struct {
            u32 op:7;
            u32 rd:5;
            u32 func3:3;
            u32 rs1:5;
            u32 rs2:5;
            u32 func7:7;
        } r;

        struct {
            u32 op:7;
            u32 imm5:5; // imm[4:0]
            u32 func3:3;
            u32 rs1:5;
            u32 rs2:5;
            u32 imm7:7; // imm[11:5]
        } s;

        struct {
            u32 op:7;
            u32 imm5:5; // imm[4:1|11]
            u32 func3:3;
            u32 rs1:5;
            u32 rs2:5;
            u32 imm7:7; // imm[12|10:5]
        } b;

        struct {
            u32 op:7;
            u32 rd:5;
            u32 imm20:20; // imm[31:12]
        } u;

        struct {
            u32 op:7;
            u32 rd:5;
            u32 imm20:20; // imm[20|10:1|11|19:12]
        } j;
        u32 instr;
    };
} rv_instr;

typedef struct riscv_exec_ctx {
    u32 *rd;
    u32 *rs1;
    u32 *rs2;
    u32 imm;
    union {
        u8 func7;
        rv_cpu *cpu;
    };
} rv_exec_ctx;

typedef struct riscv_exec {
    void (*exec)(rv_exec_ctx ctx);
} rv_exec;

struct riscv_cpu {
    /* General Purpose Registers */
    u32 xreg[32];
    /* Control and Status Registers */
    u32 csr[0xfff];
    /* Program Counter*/
    u32 pc;

    rv_bus bus;

    /* CPU context */
    u32 fetch_instr;
    rv_instr decode_instr;
    u8 pc_sel; // 1 : branch enable
};

void fetch(rv_cpu *cpu);
void decode(rv_cpu *cpu);
void execute(rv_cpu *cpu);

#endif
