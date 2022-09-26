#include "mem.h"

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
