#include "cpu.h"

static void exec_i(rv_cpu *cpu);
static void exec_r(rv_cpu *cpu);
static void exec_s(rv_cpu *cpu);
static void exec_b(rv_cpu *cpu);
static void exec_u(rv_cpu *cpu);
static void exec_j(rv_cpu *cpu);

static u32 sign_extend(u32 val, u32 bit)
{
    if (val && (1 << (bit - 1)))
        val |= 0xfffff000;
    return val;
}

void exec_addi(rv_exec_ctx ctx)
{
    *ctx.rd = *ctx.rs1 + ctx.imm;
}

void exec_slli(rv_exec_ctx ctx)
{

}

void exec_slti(rv_exec_ctx ctx)
{

}

void exec_sltiu(rv_exec_ctx ctx)
{

}

void exec_xori(rv_exec_ctx ctx)
{

}

void exec_srli_srai(rv_exec_ctx ctx)
{

}

void exec_ori(rv_exec_ctx ctx)
{

}

void exec_andi(rv_exec_ctx ctx)
{

}

rv_exec i_exec_entry[] = {
    [0x0] = {&exec_addi},
    [0x1] = {&exec_slli},
    [0x2] = {&exec_slti},
    [0x3] = {&exec_sltiu},
    [0x4] = {&exec_xori},
    [0x5] = {&exec_srli_srai},
    [0x6] = {&exec_ori},
    [0x7] = {&exec_andi},
};

void execute(rv_cpu *cpu)
{

    PIPE_DBG("-->[E]\n");

    switch (cpu->decode_instr.type) {
    case I_TYPE_LOAD:
    case I_TYPE:
    case I_TYPE_JARL:
    case I_TYPE_ENV:
        exec_i(cpu);
        break;
    case R_TYPE:
        exec_r(cpu);
        break;
    case S_TYPE:
        exec_s(cpu);
        break;
    case B_TYPE:
        exec_b(cpu);
        break;
    case U_TYPE_LUI:
    case U_TYPE_AUIPC:
        exec_u(cpu);
        break;
    case J_TYPE:
        exec_j(cpu);
        break;
    default:
        fprintf(stdout, "%s, Not Imp this OP_TYPE (0x%x) \n", __func__,
               cpu->decode_instr.type);
        exit(-1);
    }
}

static void exec_i(rv_cpu *cpu)
{
    rv_exec_ctx ctx = {0};
    rv_instr instr = cpu->decode_instr;
    ctx.imm = sign_extend(instr.i.imm, 12);
    ctx.rd = &cpu->reg.xreg[instr.i.rd];
    ctx.rs1 = &cpu->reg.xreg[instr.i.rs1];

    i_exec_entry[instr.i.func3].exec(ctx);
}

static void exec_r(rv_cpu *cpu)
{
}

static void exec_s(rv_cpu *cpu)
{
}

static void exec_b(rv_cpu *cpu)
{
}

static void exec_u(rv_cpu *cpu)
{
}

static void exec_j(rv_cpu *cpu)
{
}
