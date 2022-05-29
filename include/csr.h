#ifndef _CSR_H_
#define _CSR_H_

enum {
    MSTATUS = 0x300,
    MISA = 0x301,
    MIE = 0x304,
    MTVEC = 0x305,
    MSCRATCH = 0x340,
    MEPC = 0x341,
    MCAUSE = 0x342,
    MTVAL = 0x343,
    MIP = 0x344,
    TIME = 0xc01,
    MHARTID = 0xf14,
};

/* MSTATUS fields */
#define MSTATUS_MIE         0x8

/* MIP fields */
#define MIP_MSIP            0x8
#define MIP_MTIP            0x80
#define MIP_MEIP            0x800

#endif
