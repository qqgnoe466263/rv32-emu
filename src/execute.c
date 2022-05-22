#include "cpu.h"

char *reg_abi[] = {
    "zr", "ra", "sp", "gp", "tp",  "t0",  "t1", "t2", "s0", "s1", "a0",
    "a1", "a2", "a3", "a4", "a5",  "a6",  "a7", "s2", "s3", "s4", "s5",
    "s6", "s7", "s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6"};

static void exec_i(rv_cpu *cpu);
static void exec_i_load(rv_cpu *cpu);
static void exec_i_jalr(rv_cpu *cpu);
static void exec_r(rv_cpu *cpu);
static void exec_s(rv_cpu *cpu);
static void exec_b(rv_cpu *cpu);
static void exec_u(rv_cpu *cpu);
static void exec_j(rv_cpu *cpu);

static u32 sign_extend(u32 val, u32 bit)
{
    if (val & (1 << (bit - 1)))
        val |= 0xfffff000;
    return val;
}

/* I type */

void exec_addi(rv_exec_ctx ctx)
{
    *ctx.rd = *ctx.rs1 + ctx.imm;
}

void exec_slli(rv_exec_ctx ctx)
{
    *ctx.rd = *ctx.rs1 << (ctx.imm & 0x1f);
}

void exec_slti(rv_exec_ctx ctx)
{
    *ctx.rd = (*ctx.rs1 < ctx.imm) ? 1 : 0;
}

void exec_sltiu(rv_exec_ctx ctx)
{
    *ctx.rd = (*ctx.rs1 < ctx.imm) ? 1 : 0;
}

void exec_xori(rv_exec_ctx ctx)
{
    *ctx.rd = *ctx.rs1 ^ ctx.imm;
}

void exec_srli_srai(rv_exec_ctx ctx)
{
    u32 imm5_11 = (ctx.imm >> 5) & 0x7f;
    u32 imm0_4 = ctx.imm & 0x1f;

    if (imm5_11 == 0x20) { // srai
        *ctx.rd = *ctx.rs1 >> imm0_4;
    } else { // srli
        EXECUTE_DBG("%s, Not Imp", __func__);
        exit(-1);
    }
}

void exec_ori(rv_exec_ctx ctx)
{
    *ctx.rd = *ctx.rs1 | ctx.imm;
}

void exec_andi(rv_exec_ctx ctx)
{
    *ctx.rd = *ctx.rs1 & ctx.imm;
}

/* R type */

void exec_add_sub(rv_exec_ctx ctx)
{
    if (ctx.func7 == 0x20)
        *ctx.rd = *ctx.rs1 - *ctx.rs2;
    else
        *ctx.rd = *ctx.rs1 + *ctx.rs2;
}

void exec_sll(rv_exec_ctx ctx)
{
    *ctx.rd = *ctx.rs1 << *ctx.rs2;
}

void exec_slt(rv_exec_ctx ctx)
{
    *ctx.rd = (*ctx.rs1 < *ctx.rs2) ? 1 : 0;
}

void exec_sltu(rv_exec_ctx ctx)
{
    *ctx.rd = (*ctx.rs1 < *ctx.rs2) ? 1 : 0;
}

void exec_xor(rv_exec_ctx ctx)
{
    *ctx.rd = *ctx.rs1 ^ *ctx.rs2;
}

void exec_srl_sra(rv_exec_ctx ctx)
{

    if (ctx.func7 == 0x20) { // sra
        *ctx.rd = *ctx.rs1 >> *ctx.rs2;
    } else { // srl
        EXECUTE_DBG("%s, Not Imp", __func__);
        exit(-1);
    }
}

void exec_or(rv_exec_ctx ctx)
{
    *ctx.rd = *ctx.rs1 | *ctx.rs2;
}

void exec_and(rv_exec_ctx ctx)
{
    *ctx.rd = *ctx.rs1 & *ctx.rs2;
}

/* S type */

void exec_sb(rv_exec_ctx ctx)
{
    write_bus(&ctx.cpu->bus,
             (*ctx.rs1 + ctx.imm), *ctx.rs2, 1);
}

void exec_sh(rv_exec_ctx ctx)
{
    write_bus(&ctx.cpu->bus,
             (*ctx.rs1 + ctx.imm), *ctx.rs2, 2);
}

void exec_sw(rv_exec_ctx ctx)
{
    write_bus(&ctx.cpu->bus,
             (*ctx.rs1 + ctx.imm), *ctx.rs2, 4);
}

/* I type (load) */

void exec_lb(rv_exec_ctx ctx)
{
    *ctx.rd = (u8)read_bus(&ctx.cpu->bus, *ctx.rs1 + ctx.imm, 1);
}

void exec_lh(rv_exec_ctx ctx)
{
    *ctx.rd = (u16)read_bus(&ctx.cpu->bus, *ctx.rs1 + ctx.imm, 2);
}

void exec_lw(rv_exec_ctx ctx)
{
    *ctx.rd = read_bus(&ctx.cpu->bus, *ctx.rs1 + ctx.imm, 4);
}

void exec_lbu(rv_exec_ctx ctx)
{
}

void exec_lhu(rv_exec_ctx ctx)
{
}

/* B type */

void exec_beq(rv_exec_ctx ctx)
{
    if (*ctx.rs1 == *ctx.rs2) {
        ctx.cpu->pc += ctx.imm;
        ctx.cpu->pc_sel = 1;
    }
}

void exec_bne(rv_exec_ctx ctx)
{
    if (*ctx.rs1 != *ctx.rs2) {
        ctx.cpu->pc += ctx.imm;
        ctx.cpu->pc_sel = 1;
    }
}

void exec_blt(rv_exec_ctx ctx)
{
    if ((s32)*ctx.rs1 < (s32)*ctx.rs2) {
        ctx.cpu->pc += ctx.imm;
        ctx.cpu->pc_sel = 1;
    }
}

void exec_bge(rv_exec_ctx ctx)
{
    if ((s32)*ctx.rs1 >= (s32)*ctx.rs2) {
        ctx.cpu->pc += ctx.imm;
        ctx.cpu->pc_sel = 1;
    }
}

void exec_bltu(rv_exec_ctx ctx)
{
}

void exec_bgeu(rv_exec_ctx ctx)
{
}

/* I type (jalr) */

void exec_jalr(rv_exec_ctx ctx)
{
    *ctx.rd = ctx.cpu->pc + 4;
    ctx.cpu->pc = (*ctx.rs1 + ctx.imm);
    ctx.cpu->pc_sel = 1;

    if (ctx.cpu->pc == 0x0) {
        printf("Execute done\n");
        exit(0);
    }

#if CONFIG_FETCH_DBG
    FETCH_DBG("Ret to Func_0x%x, ret_val : 0x%x\n",
              ctx.cpu->pc,
              ctx.cpu->xreg[10]);
#endif
}

/* J type */

void exec_jal(rv_exec_ctx ctx)
{
    *ctx.rd = ctx.cpu->pc + 4;
    ctx.cpu->pc += ctx.imm;
    ctx.cpu->pc_sel = 1;
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

rv_exec r_exec_entry[] = {
    [0x0] = {&exec_add_sub},
    [0x1] = {&exec_sll},
    [0x2] = {&exec_slt},
    [0x3] = {&exec_sltu},
    [0x4] = {&exec_xor},
    [0x5] = {&exec_srl_sra},
    [0x6] = {&exec_or},
    [0x7] = {&exec_and},
};

rv_exec s_exec_entry[] = {
    [0x0] = {&exec_sb},
    [0x1] = {&exec_sh},
    [0x2] = {&exec_sw},
};

rv_exec i_load_exec_entry[] = {
    [0x0] = {&exec_lb},
    [0x1] = {&exec_lh},
    [0x2] = {&exec_lw},
    //[0x4] = {&exec_lbu},
    //[0x5] = {&exec_lhu},
};

rv_exec i_jalr_exec_entry[] = {
    [0x0] = {&exec_jalr},
};

rv_exec b_exec_entry[] = {
    [0x0] = {&exec_beq},
    [0x1] = {&exec_bne},
    [0x4] = {&exec_blt},
    [0x5] = {&exec_bge},
    //[0x6] = {&exec_bltu},
    //[0x7] = {&exec_bgeu},
};

void execute(rv_cpu *cpu)
{
    EXECUTE_DBG("-->[E] ");

    switch (cpu->decode_instr.type) {
    case I_TYPE_LOAD:
        exec_i_load(cpu);
        break;
    case I_TYPE:
        exec_i(cpu);
        break;
    case I_TYPE_JARL:
        exec_i_jalr(cpu);
        break;
    //case I_TYPE_ENV:
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
    //case U_TYPE_LUI:
    //case U_TYPE_AUIPC:
        //exec_u(cpu);
        //break;
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
    ctx.rd = &cpu->xreg[instr.i.rd];
    ctx.rs1 = &cpu->xreg[instr.i.rs1];

    if (instr.i.func3 > ARRAY_SIZE(i_exec_entry)) {
        fprintf(stdout, "%s, FUNC3(0x%x) Not Imp\n",
                __func__, instr.i.func3);
        exit(-1);
    }

    if (!i_exec_entry[instr.i.func3].exec) {
        fprintf(stdout, "%s, FUNC3(0x%x) Not Imp\n",
                __func__, instr.i.func3);
        exit(-1);
    }

    EXECUTE_DBG("%12s, rd(%s) : 0x%08x, rs1(%s) : 0x%08x, imm : 0x%08x\n",
             __func__, reg_abi[instr.i.rd], *ctx.rd, 
             reg_abi[instr.i.rs1], *ctx.rs1, ctx.imm);

    i_exec_entry[instr.i.func3].exec(ctx);
}

static void exec_i_load(rv_cpu *cpu)
{
    rv_exec_ctx ctx = {0};
    rv_instr instr = cpu->decode_instr;
    ctx.imm = sign_extend(instr.i.imm, 12);
    ctx.rd = &cpu->xreg[instr.i.rd];
    ctx.rs1 = &cpu->xreg[instr.i.rs1];
    ctx.cpu = cpu;

    if (instr.i.func3 > ARRAY_SIZE(i_load_exec_entry)) {
        fprintf(stdout, "%s, FUNC3(0x%x) Not Imp\n",
                __func__, instr.i.func3);
        exit(-1);
    }

    if (!i_load_exec_entry[instr.i.func3].exec) {
        fprintf(stdout, "%s, FUNC3(0x%x) Not Imp\n",
                __func__, instr.i.func3);
        exit(-1);
    }

    EXECUTE_DBG("%12s, rd(%s) : 0x%08x, rs1(%s) : 0x%08x, imm : 0x%08x\n",
             __func__, reg_abi[instr.i.rd], *ctx.rd, 
             reg_abi[instr.i.rs1], *ctx.rs1, ctx.imm);

    i_load_exec_entry[instr.i.func3].exec(ctx);
}

static void exec_i_jalr(rv_cpu *cpu)
{
    rv_exec_ctx ctx = {0};
    rv_instr instr = cpu->decode_instr;
    ctx.imm = sign_extend(instr.i.imm, 12);
    ctx.rd = &cpu->xreg[instr.i.rd];
    ctx.rs1 = &cpu->xreg[instr.i.rs1];
    ctx.cpu = cpu;

    if (instr.i.func3 > ARRAY_SIZE(i_jalr_exec_entry)) {
        fprintf(stdout, "%s, FUNC3(0x%x) Not Imp\n",
                __func__, instr.i.func3);
        exit(-1);
    }

    if (!i_jalr_exec_entry[instr.i.func3].exec) {
        fprintf(stdout, "%s, FUNC3(0x%x) Not Imp\n",
                __func__, instr.i.func3);
        exit(-1);
    }

    EXECUTE_DBG("%12s, rd(%s) : 0x%08x, rs1(%s) : 0x%08x, imm : 0x%08x\n",
             __func__, reg_abi[instr.i.rd], *ctx.rd, 
             reg_abi[instr.i.rs1], *ctx.rs1, ctx.imm);

    i_jalr_exec_entry[instr.i.func3].exec(ctx);
}

static void exec_r(rv_cpu *cpu)
{
    rv_exec_ctx ctx = {0};
    rv_instr instr = cpu->decode_instr;
    ctx.rd = &cpu->xreg[instr.r.rd];
    ctx.rs1 = &cpu->xreg[instr.r.rs1];
    ctx.rs2 = &cpu->xreg[instr.r.rs2];
    ctx.func7 = instr.r.func7;

    if (instr.r.func3 > ARRAY_SIZE(r_exec_entry)) {
        fprintf(stdout, "%s, FUNC3(0x%x) Not Imp\n",
                __func__, instr.r.func3);
        exit(-1);
    }

    if (!r_exec_entry[instr.r.func3].exec) {
        fprintf(stdout, "%s, FUNC3(0x%x) Not Imp\n",
                __func__, instr.r.func3);
        exit(-1);
    }

    EXECUTE_DBG("%12s, rd(%s) : 0x%08x, rs1(%s) : 0x%08x, rs2(%s) : 0x%08x\n",
             __func__, reg_abi[instr.r.rd], *ctx.rd, reg_abi[instr.r.rs1], 
             *ctx.rs1, reg_abi[instr.r.rs2], *ctx.rs2);

    r_exec_entry[instr.r.func3].exec(ctx);
}

static void exec_s(rv_cpu *cpu)
{
    rv_exec_ctx ctx = {0};
    rv_instr instr = cpu->decode_instr;
    ctx.rs1 = &cpu->xreg[instr.s.rs1];
    ctx.rs2 = &cpu->xreg[instr.s.rs2];
    ctx.imm = sign_extend(instr.s.imm7 << 5 | instr.s.imm5, 12);
    ctx.cpu = cpu;

    if (instr.s.func3 > ARRAY_SIZE(s_exec_entry)) {
        fprintf(stdout, "%s, FUNC3(0x%x) Not Imp\n",
                __func__, instr.s.func3);
        exit(-1);
    }

    if (!s_exec_entry[instr.s.func3].exec) {
        fprintf(stdout, "%s, FUNC3(0x%x) Not Imp\n",
                __func__, instr.s.func3);
        exit(-1);
    }

    EXECUTE_DBG("%12s,rs1(%s) : 0x%08x, rs2(%s) : 0x%08x, imm : 0x%08x\n",
             __func__, reg_abi[instr.s.rs1], *ctx.rs1, reg_abi[instr.s.rs2], 
             *ctx.rs2, ctx.imm);

    s_exec_entry[instr.s.func3].exec(ctx);
}

static void exec_b(rv_cpu *cpu)
{
    rv_exec_ctx ctx = {0};
    rv_instr instr = cpu->decode_instr;
    ctx.rs1 = &cpu->xreg[instr.b.rs1];
    ctx.rs2 = &cpu->xreg[instr.b.rs2];

    ctx.imm =
    sign_extend((instr.b.imm5 & 0b00001) << 11   | // bit 11
                (instr.b.imm5 & 0b11110)         | // bit 1~4
                (instr.b.imm7 & 0b1000000) << 12 | // bit 12
                (instr.b.imm7 & 0b0111111) << 5,   // bit 5~10
                12);
    ctx.cpu = cpu;

    if (instr.b.func3 > ARRAY_SIZE(b_exec_entry)) {
        fprintf(stdout, "%s, FUNC3(0x%x) Not Imp\n",
                __func__, instr.b.func3);
        exit(-1);
    }

    if (!b_exec_entry[instr.b.func3].exec) {
        fprintf(stdout, "%s, FUNC3(0x%x) Not Imp\n",
                __func__, instr.b.func3);
        exit(-1);
    }

    EXECUTE_DBG("%12s,rs1(%s) : 0x%08x, rs2(%s) : 0x%08x, imm : 0x%08x\n",
             __func__, reg_abi[instr.b.rs1], *ctx.rs1, reg_abi[instr.b.rs2], 
             *ctx.rs2, ctx.imm);

    b_exec_entry[instr.b.func3].exec(ctx);
}

static void exec_u(rv_cpu *cpu)
{
    EXECUTE_DBG("\n");
}

static void exec_j(rv_cpu *cpu)
{
    rv_exec_ctx ctx = {0};
    rv_instr instr = cpu->decode_instr;
    ctx.rd = &cpu->xreg[instr.j.rd];
    ctx.cpu = cpu;

    ctx.imm =
    sign_extend((instr.j.imm20 & 0b10000000000000000000) << 20 | // bit 20
                (instr.j.imm20 & 0b00000000000011111111) << 12 | // bit 19~12
                (instr.j.imm20 & 0b00000000000100000000) << 3  | // bit 11
                (instr.j.imm20 & 0b01111111111000000000) >> 8,   // bit 10~1
                20);

#if CONFIG_FETCH_DBG
    if (instr.j.rd == 1) {
        FETCH_DBG("Jump to Func_0x%x(arg0:0x%x)\n",
                  ctx.cpu->pc + ctx.imm,
                  ctx.cpu->xreg[10]);
    }
#endif

    EXECUTE_DBG("%12s, rd(%s) : 0x%08x, imm : 0x%08x\n",
             __func__, reg_abi[instr.j.rd], *ctx.rd, ctx.imm);

    exec_jal(ctx);
}
