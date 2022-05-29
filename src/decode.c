#include "cpu.h"

char *optype[] = {
    [I_TYPE_LOAD]  = "I_TYPE_LOAD",
    [I_TYPE]       = "I_TYPE",
    [U_TYPE_AUIPC] = "U_TYPE_AUIPC",
    [S_TYPE]       = "S_TYPE",
    [R_TYPE]       = "R_TYPE",
    [U_TYPE_LUI]   = "U_TYPE_LUI",
    [B_TYPE]       = "B_TYPE",
    [I_TYPE_JARL]  = "I_TYPE_JARL",
    [J_TYPE]       = "J_TYPE",
    [I_TYPE_SYS]   = "I_TYPE_SYS",
};

#if CONFIG_DECODE_DBG
static void decode_i_type_instr(rv_instr instr)
{
    DECODE_DBG("rd : 0x%x, func3 : 0x%x, "
             "rs1 : 0x%x, imm : 0x%x\n",
            instr.i.rd, instr.i.func3,
            instr.i.rs1, instr.i.imm);
}


static void decode_r_type_instr(rv_instr instr)
{
    DECODE_DBG("rd : 0x%x, func3 : 0x%x, "
             "rs1 : 0x%x, rs2 : 0x%x, func7 : 0x%x\n",
            instr.r.rd, instr.r.func3,
            instr.r.rs1, instr.r.rs2,
            instr.r.func7);
}

static void decode_s_type_instr(rv_instr instr)
{
    DECODE_DBG("imm5 : 0x%x, func3 : 0x%x, "
             "rs1 : 0x%x, imm7 : 0x%x\n",
            instr.s.imm5, instr.s.func3,
            instr.s.rs1, instr.s.imm7);
}

static void decode_b_type_instr(rv_instr instr)
{
    DECODE_DBG("imm5 : 0x%x, func3 : 0x%x, "
             "rs1 : 0x%x, imm7 : 0x%x\n",
            instr.b.imm5, instr.b.func3,
            instr.b.rs1, instr.b.imm7);
}

static void decode_u_type_instr(rv_instr instr)
{
    DECODE_DBG("rd : 0x%x,  imm20 : 0x%x\n",
            instr.u.rd, instr.u.imm20);
}

static void decode_j_type_instr(rv_instr instr)
{
    DECODE_DBG("rd : 0x%x, imm20 : 0x%x\n",
            instr.j.rd, instr.j.imm20);
}
#endif

void decode(rv_cpu *cpu)
{

    cpu->decode_instr.instr = cpu->fetch_instr;
    cpu->decode_instr.type = cpu->fetch_instr & 0x7f;

    DECODE_DBG("->[D]  [%s] ", optype[cpu->decode_instr.type]);

#if CONFIG_DECODE_DBG
    switch (cpu->decode_instr.type) {
    case I_TYPE_FENCE:
        break;
    case I_TYPE_LOAD:
    case I_TYPE:
    case I_TYPE_JARL:
    case I_TYPE_SYS:
        decode_i_type_instr(cpu->decode_instr);
        break;
#if CONFIG_RV32A_EXTENSION
    case RV32A_TYPE:
#endif
    case R_TYPE:
        decode_r_type_instr(cpu->decode_instr);
        break;
    case S_TYPE:
        decode_s_type_instr(cpu->decode_instr);
        break;
    case B_TYPE:
        decode_b_type_instr(cpu->decode_instr);
        break;
    case U_TYPE_LUI:
    case U_TYPE_AUIPC:
        decode_u_type_instr(cpu->decode_instr);
        break;
    case J_TYPE:
        decode_j_type_instr(cpu->decode_instr);
        break;
    default:
        fprintf(stdout, "%s, Not Imp this OP_TYPE (0x%x) \n", __func__,
               cpu->decode_instr.type);
        exit(-1);
    }
#endif

}



