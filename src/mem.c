#include "mem.h"
#include "debug.h"

s32 read_mem(rv_mem *mem, u32 addr, u8 byte)
{
    u8 *target = mem->mem + addr;
    u32 val;

    switch (byte) {
    case 1:
        val = *(u8 *)target;
        break;
    case 2:
        val = *(u16 *)target;
        break;
    case 4:
        val = *(u32 *)target;
        break;
    }

    RW_DBG("[%10s] BYTE : %d, val = 0x%x \n", __func__, byte, val);
    return val;
}

void write_mem(rv_mem *mem, u32 addr, u32 data, u8 byte)
{
    u32 *target = (u32 *)(mem->mem + addr);

    switch (byte) {
    case 1:
        *(u8 *)target = (data & 0xff);
        break;
    case 2:
        *(u16 *)target = (data & 0xffff);
        break;
    case 4:
        *(u32 *)target = (data & 0xffffffff);
    }

    RW_DBG("[%10s] BYTE : %d, val = 0x%x \n", __func__, byte, *target);
}


