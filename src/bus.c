#include "bus.h"
#include "debug.h"

#if CONFIG_RW_DBG
char *mem_map_string[] = {
    "BOOT_ROM", "CLINT", "PLIC",
    "UART0", "VIRTIO", "KERNBASE",
};
#endif

s32 read_bus(rv_bus *bus, u32 addr, u8 byte)
{
    int i;

    if (byte > 4) {
        RW_DBG("%s, %d-byte > 4", __func__, byte);
        return -1;
    }

    if (addr > MEM_SIZE) {
        RW_DBG("%s, addr(0x%x) > MEM SIZE(0x%lx)\n", __func__, addr, MEM_SIZE);
        return -1;
    }

    for (i = 0; i < KERNBASE; i++) {
        if (addr >= mem_map[i].base &&
            addr < (mem_map[i].base + mem_map[i].size))
            break;
    }

    if ((addr > 0xf0000000)) {
        RW_DBG("[%10s] from STACK addr(0x%x)\n", __func__, addr);
    } else {
        addr -= mem_map[i].base;
        RW_DBG("[%10s] %s, offset : 0x%x\n", __func__, mem_map_string[i], addr);
    }
    return read_mem(&bus->vmem, addr, byte);
}

void write_bus(rv_bus *bus, u32 addr, u32 data, u8 byte)
{
    int i;

    if (byte > 4) {
        RW_DBG("%s, %d-byte > 4\n", __func__, byte);
        exit(-1);
    }

    if (addr > MEM_SIZE) {
        RW_DBG("%s, addr(0x%x) > MEM SIZE(0x%lx)\n", __func__, addr, MEM_SIZE);
        exit(-1);
    }

    for (i = 0; i < KERNBASE; i++) {
        if (addr >= mem_map[i].base &&
            addr < (mem_map[i].base + mem_map[i].size))
            break;
    }

    if ((addr > 0xf0000000)) {
        RW_DBG("[%10s] to STACK addr(0x%x)\n", __func__, addr);
    } else {
        addr -= mem_map[i].base;
        RW_DBG("[%10s] %s, offset : 0x%x\n", __func__, mem_map_string[i], addr);
    }
    write_mem(&bus->vmem, addr, data, byte);
}
