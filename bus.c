#include "bus.h"

struct rv32_bus *bus_init()
{
    struct rv32_bus *bus = malloc(sizeof(struct rv32_bus));

    bus->ram = malloc(sizeof(char) * RAM_SIZE);
    bus->boot = malloc(sizeof(struct rv32_boot));
    bus->uart0 = uart_init();
    bus->clint = clint_init();
    bus->plic = plic_init();
    bus->virtio = virtio_init(NULL);

    return bus;
}

exception_t read_bus(struct rv32_bus *bus, u32 addr, u32 size, u32 *result)
{
    if (RANGE_CHECK(addr, BOOT_ROM_BASE, 0xf000))
        return read_boot(bus->boot->mem, addr, size, result);
    if (RAM_BASE <= addr)
        return read_ram(bus->ram, addr, size, result);
    if (RANGE_CHECK(addr, CLINT_BASE, CLINT_SIZE))
        return read_clint(bus->clint, addr, size, result);
    if (RANGE_CHECK(addr, PLIC_BASE, PLIC_SIZE))
        return read_plic(bus->plic, addr, size, result);
    /* UART RX */
    if (RANGE_CHECK(addr, UART_BASE, UART_SIZE))
        return read_uart(bus->uart0, addr, size, result);
    if (RANGE_CHECK(addr, VIRTIO_BASE, VIRTIO_SIZE))
        return read_virtio(bus->virtio, addr, size, result);

    return LOAD_ACCESS_FAULT;
}

exception_t write_bus(struct rv32_bus *bus, u32 addr, u32 size, u32 value)
{
    if (RAM_BASE <= addr)
        return write_ram(bus->ram, addr, size, value);
    if (RANGE_CHECK(addr, CLINT_BASE, CLINT_SIZE))
        return write_clint(bus->clint, addr, size, value);
    if (RANGE_CHECK(addr, PLIC_BASE, PLIC_SIZE))
        return write_plic(bus->plic, addr, size, value);
    /* UART TX */
    if (RANGE_CHECK(addr, UART_BASE, UART_SIZE))
        return write_uart(bus->uart0, addr, size, value);
    if (RANGE_CHECK(addr, VIRTIO_BASE, VIRTIO_SIZE))
        return write_virtio(bus->virtio, addr, size, value);

    return STORE_AMO_ACCESS_FAULT;
}

void bus_disk_access(struct rv32_bus *bus)
{
    u32 desc_addr = virtio_desc_addr(bus->virtio);
    u32 avail_addr = desc_addr + (VIRTIO_DESC_NUM * 0x10),
        used_addr = desc_addr + 4096;

#if 0  // TODO
    desc_addr = 0xc776a000;
    avail_addr = 0xc776a040;
    used_addr = 0xc776b000;

    exception_t e = mmu_translate(core, desc_addr, LOAD_PAGE_FAULT, &desc_addr,
                                  ACCESS_LOAD);
    if (e != OK)
        exit(0);

    e = mmu_translate(core, avail_addr, LOAD_PAGE_FAULT, &avail_addr,
                      ACCESS_LOAD);
    if (e != OK)
        exit(0);

    e = mmu_translate(core, used_addr, LOAD_PAGE_FAULT, &used_addr,
                      ACCESS_LOAD);
    if (e != OK)
        exit(0);
#endif

    u32 offset;
    if (read_bus(bus, avail_addr + 2, 16, &offset) != OK)
        pr_err("read offset");

    u32 idx;
    if (read_bus(bus, avail_addr + (offset % VIRTIO_DESC_NUM) + 4, 16, &idx) !=
        OK)
        pr_err("read index");

    u32 desc_addr0 = desc_addr + VIRTIO_VRING_DESC_SIZE * idx;
    u32 addr0;
    if (read_bus(bus, desc_addr0, 32, &addr0) != OK)
        pr_err("read address field in descriptor");

    u32 len0;
    if (read_bus(bus, desc_addr0 + 8, 32, &len0) != OK)
        pr_err("read length field in descriptor");

    u32 flags0;
    if (read_bus(bus, desc_addr0 + 12, 16, &flags0) != OK)
        pr_err("read flags field in descriptor");

    u32 next0;
    if (read_bus(bus, desc_addr0 + 14, 16, &next0) != OK)
        pr_err("read next field in descriptor");

    u32 desc_addr1 = desc_addr + VIRTIO_VRING_DESC_SIZE * next0;
    u32 addr1;
    if (read_bus(bus, desc_addr1, 32, &addr1) != OK)
        pr_err("read address field in descriptor");

    u32 len1;
    if (read_bus(bus, desc_addr1 + 8, 32, &len1) != OK)
        pr_err("read length field in descriptor");

    u32 flags1;
    if (read_bus(bus, desc_addr1 + 12, 16, &flags1) != OK)
        pr_err("read flags field in descriptor");

    u32 next1;
    if (read_bus(bus, desc_addr1 + 14, 16, &next1) != OK)
        pr_err("read next field in descriptor");

    u32 desc_addr2 = desc_addr + VIRTIO_VRING_DESC_SIZE * next1;
    u32 addr2;
    if (read_bus(bus, desc_addr2, 32, &addr2) != OK)
        pr_err("read address field in descriptor");

    u32 len2;
    if (read_bus(bus, desc_addr2 + 8, 32, &len2) != OK)
        pr_err("read length field in descriptor");

    u32 flags2;
    if (read_bus(bus, desc_addr2 + 12, 16, &flags2) != OK)
        pr_err("read flags field in descriptor");

    u32 next2;
    if (read_bus(bus, desc_addr2 + 14, 16, &next2) != OK)
        pr_err("read next field in descriptor");

    u32 blk_type;
    if (read_bus(bus, addr0, 32, &blk_type) != OK)
        pr_err("read sector field in virtio_blk_outhdr");

    u32 blk_sector;
    if (read_bus(bus, addr0 + 8, 32, &blk_sector) != OK)
        pr_err("read sector field in virtio_blk_outhdr");

    if (blk_type == 1) {
        // write
        for (u32 i = 0; i < len1; i++) {
            u32 data;
            if (read_bus(bus, addr1 + i, 8, &data) != OK)
                pr_err("read from RAM");
            virtio_disk_write(bus->virtio, blk_sector * 512 + i, data);
        }
    } else {
        for (u32 i = 0; i < len1; i++) {
            u32 data = virtio_disk_read(bus->virtio, blk_sector * 512 + i);
            if (write_bus(bus, addr1 + i, 8, data) != OK)
                pr_err("write to RAM");
        }
    }

    if (write_bus(bus,
                  used_addr + 8 + ((bus->virtio->id % VIRTIO_DESC_NUM) * 8), 16,
                  len1 + len2) != OK)
        pr_err("write to RAM");

    if (write_bus(bus,
                  used_addr + 4 + ((bus->virtio->id % VIRTIO_DESC_NUM) * 8), 16,
                  idx) != OK)
        pr_err("write to RAM");

    u32 new_id = virtio_new_id(bus->virtio);
    if (write_bus(bus, used_addr + 2, 16, new_id) != OK)
        pr_err("write to RAM");
}
