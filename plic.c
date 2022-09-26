#include "plic.h"

/* TODO */
static int is_claim_complete = 0;

struct rv32_plic *plic_init()
{
    return malloc(sizeof(struct rv32_plic));
}

exception_t read_plic(struct rv32_plic *plic, u32 addr, u32 size, u32 *result)
{
    if (size != 32)
        return LOAD_ACCESS_FAULT;

    switch (addr) {
    case PLIC_PENDING:
        *result = plic->pending;
        break;
    case PLIC_ENABLE:
        *result = plic->enable;
        break;
    case PLIC_PRIORITY:
        *result = plic->priority;
        break;
    case PLIC_CLAIM:
        *result = plic->claim;
        break;
    default:
        *result = 0;
    }

    return OK;
}

exception_t write_plic(struct rv32_plic *plic, u32 addr, u32 size, u32 value)
{
    if (size != 32)
        return STORE_AMO_ACCESS_FAULT;

    switch (addr) {
    case PLIC_PENDING:
        plic->pending = value;
        break;
    case PLIC_ENABLE:
        plic->enable = value;
        break;
    case PLIC_PRIORITY:
        plic->priority = value;
        break;
    case PLIC_CLAIM:
        /* TODO */
        if (!(is_claim_complete == value)) {
            plic->claim = value;
            is_claim_complete = value;
        } else {
            plic->claim = 0;
            is_claim_complete = 0;
        }
        break;
    }

    return OK;
}
