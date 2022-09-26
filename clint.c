#include "clint.h"

struct rv32_clint *clint_init()
{
    struct rv32_clint *clint = malloc(sizeof(struct rv32_clint));
    clint->mtimecmp = 0;
    clint->mtime = 0;

    return clint;
}

exception_t read_clint(struct rv32_clint *clint,
                       u32 addr,
                       u32 size,
                       u32 *result)
{
    if (size != 32)
        return LOAD_ACCESS_FAULT;

    switch (addr) {
    case CLINT_MTIMECMP:
        *result = clint->mtimecmp;
        break;
    case CLINT_MTIME:
        *result = clint->mtime;
        break;
    default:
        *result = 0;
    }

    return OK;
}

exception_t write_clint(struct rv32_clint *clint, u32 addr, u32 size, u32 value)
{
    if (size != 32)
        return STORE_AMO_ACCESS_FAULT;

    switch (addr) {
    case CLINT_MTIMECMP:
        clint->mtimecmp = value;
        break;
    case CLINT_MTIME:
        clint->mtime = value;
        break;
    }

    return OK;
}
