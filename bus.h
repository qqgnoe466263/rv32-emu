#ifndef _BUS_H_
#define _BUS_H_

#include "boot.h"
#include "clint.h"
#include "common.h"
#include "mem.h"
#include "plic.h"
#include "trap.h"
#include "uart.h"
#include "virtio.h"

#define RANGE_CHECK(x, minx, size) \
    ((int) ((x - minx) | (minx + size - 1 - x)) >= 0)

struct rv32_bus {
    u8 *ram;
    struct rv32_boot *boot;
    struct rv32_uart *uart0;
    struct rv32_clint *clint;
    struct rv32_plic *plic;
    struct rv32_virtio *virtio;

#if CONFIG_ARCH_TEST
    struct rv32_sig sig;
#endif
};

struct rv32_bus *bus_init();
void bus_disk_access(struct rv32_bus *bus);
exception_t read_bus(struct rv32_bus *bus, u32 addr, u32 size, u32 *result);
exception_t write_bus(struct rv32_bus *bus, u32 addr, u32 size, u32 value);

#endif
