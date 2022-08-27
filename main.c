#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "elf.h"

#define RAM_SIZE (1024 * 1024 * 128)
#define RAM_BASE (0x80000000)

#define PAGE_SIZE (4096)

#define CLINT_BASE (0x2000000)
#define CLINT_SIZE (0x10000)
#define CLINT_MTIMECMP (CLINT_BASE + 0x4000)
#define CLINT_MTIME (CLINT_BASE + 0xbff8)

#define PLIC_BASE (0xc000000)
#define PLIC_SIZE (0x4000000)
#define PLIC_PENDING (PLIC_BASE + 0x1000)  // Start of pending array (read-only)
#define PLIC_ENABLE (PLIC_BASE + 0x2080)   // Target 0 enables
#define PLIC_PRIORITY (PLIC_BASE + 0x201000)  // Target 0 priority threshold
#define PLIC_CLAIM (PLIC_BASE + 0x201004)     // Target 0 claim/complete

#define RANGE_CHECK(x, minx, size) \
    ((int) ((x - minx) | (minx + size - 1 - x)) >= 0)

#if CONFIG_ARCH_TEST
static char signature_out_file[256];
static bool opt_arch_test = false;

/* For riscv-test */
struct rv32_sig {
    u32 start;
    u32 end;
};
#endif

typedef enum {
    OK = -1,
    INSTRUCTION_ADDRESS_MISALIGNED = 0,
    INSTRUCTION_ACCESS_FAULT = 1,
    ILLEGAL_INSTRUCTION = 2,
    BREAKPOINT = 3,
    LOAD_ADDRESS_MISALIGNED = 4,
    LOAD_ACCESS_FAULT = 5,
    STORE_AMO_ADDRESS_MISALIGNED = 6,
    STORE_AMO_ACCESS_FAULT = 7,
    INSTRUCTION_PAGE_FAULT = 12,
    LOAD_PAGE_FAULT = 13,
    STORE_AMO_PAGE_FAULT = 15,
} exception_t;

typedef enum {
    NONE = -1,
    SUPERVISOR_SOFTWARE_INTERRUPT = 1,
    MACHINE_SOFTWARE_INTERRUPT = 3,
    SUPERVISOR_TIMER_INTERRUPT = 5,
    MACHINE_TIMER_INTERRUPT = 7,
    ECALL_FROM_U_MODE = 8,
    SUPERVISOR_EXTERNAL_INTERRUPT = 9,
    MACHINE_EXTERNAL_INTERRUPT = 11,
} interrupt_t;

/* M mode CSRs */
enum {
    MSTATUS = 0x300,
    MEDELEG = 0x302,
    MIDELEG,
    MIE,  // Machine Interrupt Enable
    MTVEC = 0x305,
    MEPC = 0x341,
    MCAUSE,
    MTVAL,
    MIP,  // Machine Interrupt Pending
};

/* MSTATUS */
enum {
    MSTATUS_MIE = (1 << 3),
    MSTATUS_MPIE = (1 << 7),  // Save Previous MSTATUS_MIE value
};

/* S mode CSRs */
enum {
    SSTATUS = 0x100,
    SIE = 0x104,
    STVEC,
    SEPC = 0x141,
    SCAUSE,
    STVAL,
    SIP,
    SATP = 0x180,
};

/* MIE */
enum {
    MIE_MSIE = (1 << 3),   // software
    MIE_MTIE = (1 << 7),   // timer
    MIE_MEIE = (1 << 11),  // external
};

/* MIP */
enum {
    MIP_SSIP = (1 << 1),
    MIP_STIP = (1 << 5),
    MIP_SEIP = (1 << 9),
    MIP_MSIP = (1 << 3),
    MIP_MTIP = (1 << 7),
    MIP_MEIP = (1 << 11),
};

#define UART_BASE (0x10000000)
#define UART_SIZE (0x100)
#define UART_THR (UART_BASE + 0)  // TX
#define UART_RHR (UART_BASE + 0)  // RX
#define UART_LSR (UART_BASE + 5)
#define UART_LSR_RX_EMPTY (1 << 0)
#define UART_LSR_TX_EMPTY (1 << 5)
#define UART_LSR_THR_SR_EMPTY (1 << 6)

struct rv32_uart {
    u8 data[UART_SIZE];
    bool interrupting;

    pthread_t tid;
    pthread_mutex_t lock;
    pthread_cond_t cond;
};

struct rv32_clint {
    u32 mtime;
    u32 mtimecmp;
};

struct rv32_plic {
    u32 pending;
    u32 enable;
    u32 priority;
    u32 claim;
};

/* Virtio */
/* https://docs.oasis-open.org/virtio/virtio/v1.1/csprd01/virtio-v1.1-csprd01.html#x1-146001r1
 */
#define VIRTIO_VRING_DESC_SIZE 16
#define VIRTIO_DESC_NUM 8

#define VIRTIO_BASE (0x10001000)
#define VIRTIO_SIZE (0x1000)
/* Legacy interface */
#define VIRTIO_GUEST_PAGE_SIZE (VIRTIO_BASE + 0x28)
#define VIRTIO_QUEUE_PFN (VIRTIO_BASE + 0x40)
/* Virtio Over MMIO */
#define VIRTIO_MAGIC (VIRTIO_BASE + 0x0)
#define VIRTIO_VERSION (VIRTIO_BASE + 0x4)
#define VIRTIO_DEVICE_ID (VIRTIO_BASE + 0x8)
#define VIRTIO_VENDOR_ID (VIRTIO_BASE + 0xc)
#define VIRTIO_DEVICE_FEATURES (VIRTIO_BASE + 0x10)
#define VIRTIO_DRIVER_FEATURES (VIRTIO_BASE + 0x20)
#define VIRTIO_QUEUE_SEL (VIRTIO_BASE + 0x30)
#define VIRTIO_QUEUE_NUM_MAX (VIRTIO_BASE + 0x34)
#define VIRTIO_QUEUE_NUM (VIRTIO_BASE + 0x38)
#define VIRTIO_QUEUE_NOTIFY (VIRTIO_BASE + 0x50)
#define VIRTIO_INTERRUPT_STATUS (VIRTIO_BASE + 0x060)
#define VIRTIO_INTERRUPT_ACK (VIRTIO_BASE + 0x064)
#define VIRTIO_STATUS (VIRTIO_BASE + 0x70)

struct rv32_virtio {
    u32 id;
    u32 driver_features;
    u32 page_size;
    u32 q_sel;
    u32 q_num;
    u32 q_pfn;
    u32 q_notify;
    u32 intr_status;
    u32 intr_ack;
    u32 status;
    u8 *disk;
};

typedef enum {
    USER = 0x0,
    SUPERVISOR = 0x1,
    MACHINE = 0x3,
} core_mode_t;

struct rv32_bus {
    u8 *ram;
    struct rv32_uart *uart0;
    struct rv32_clint *clint;
    struct rv32_plic *plic;
    struct rv32_virtio *virtio;

#if CONFIG_ARCH_TEST
    struct rv32_sig sig;
#endif
};

struct rv32_ctx {
    u32 instr;
    u8 encode;  // 0: 32bits, 1: 16bits
};

struct rv32_core {
    core_mode_t mode;
    u32 xreg[32];
    u32 csr[4096];
    u32 pc;

    struct rv32_bus *bus;
    bool enable_paging;
    u32 pagetable;

    /* Runtime Context */
    struct rv32_ctx ctx;
};

void pr_err(const char *msg)
{
    fprintf(stderr, "[!] Failed to %s\n", msg);
    exit(1);
}

bool exception_is_fatal(exception_t e)
{
    switch (e) {
    case INSTRUCTION_ADDRESS_MISALIGNED:
    case INSTRUCTION_ACCESS_FAULT:
    case LOAD_ACCESS_FAULT:
    case STORE_AMO_ADDRESS_MISALIGNED:
    case STORE_AMO_ACCESS_FAULT:
        return true;
    default:
        return false;
    }
}

exception_t read_uart(struct rv32_uart *uart, u32 addr, u32 size, u32 *result)
{
    if (size != 8)
        return LOAD_ACCESS_FAULT;

    pthread_mutex_lock(&uart->lock);
    switch (addr) {
    case UART_RHR:
        pthread_cond_broadcast(&uart->cond);  // wake up thread
        uart->data[UART_LSR - UART_BASE] &= ~UART_LSR_RX_EMPTY;
    default:
        *result = uart->data[addr - UART_BASE];
    }
    pthread_mutex_unlock(&uart->lock);

    return OK;
}

exception_t write_uart(struct rv32_uart *uart, u32 addr, u32 size, u32 value)
{
    if (size != 8)
        return STORE_AMO_ACCESS_FAULT;

    pthread_mutex_lock(&uart->lock);
    switch (addr) {
    case UART_THR:
        fprintf(stdout, "%c", (value & 0xff));
        break;
    default:
        uart->data[addr - UART_BASE] = (value & 0xff);
    }
    pthread_mutex_unlock(&uart->lock);

    return OK;
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
        plic->claim = value;
        break;
    }

    return OK;
}

exception_t read_virtio(struct rv32_virtio *virtio,
                        u32 addr,
                        u32 size,
                        u32 *result)
{
    if (size != 32)
        return LOAD_ACCESS_FAULT;

    switch (addr) {
    case VIRTIO_MAGIC:
        *result = 0x74726976;
        break;
    case VIRTIO_VERSION:
        *result = 0x1;
        break;
    case VIRTIO_DEVICE_ID:
        *result = 0x2;
        break;
    case VIRTIO_VENDOR_ID:
        *result = 0x554d4551;
        break;
    case VIRTIO_DEVICE_FEATURES:
        *result = 0;
        break;
    case VIRTIO_DRIVER_FEATURES:
        *result = virtio->driver_features;
        break;
    case VIRTIO_QUEUE_NUM_MAX:
        *result = 8;
        break;
    case VIRTIO_QUEUE_PFN:
        *result = virtio->q_pfn;
        break;
    case VIRTIO_INTERRUPT_STATUS:
        *result = virtio->intr_status;
        break;
    case VIRTIO_INTERRUPT_ACK:
        *result = virtio->intr_ack;
        break;
    case VIRTIO_STATUS:
        *result = virtio->status;
        break;
    default:
        *result = 0;
    }

    return OK;
}

exception_t write_virtio(struct rv32_virtio *virtio,
                         u32 addr,
                         u32 size,
                         u32 value)
{
    if (size != 32)
        return STORE_AMO_ACCESS_FAULT;

    switch (addr) {
    case VIRTIO_DEVICE_FEATURES:
        virtio->driver_features = value;
        break;
    case VIRTIO_GUEST_PAGE_SIZE:
        virtio->page_size = value;
        break;
    case VIRTIO_QUEUE_SEL:
        virtio->q_sel = value;
        break;
    case VIRTIO_QUEUE_NUM:
        virtio->q_num = value;
        break;
    case VIRTIO_QUEUE_PFN:
        virtio->q_pfn = value;
        break;
    case VIRTIO_QUEUE_NOTIFY:
        virtio->q_notify = value;
        break;
    case VIRTIO_INTERRUPT_STATUS:
        virtio->intr_status = value;
        break;
    case VIRTIO_INTERRUPT_ACK:
        virtio->intr_ack = value;
        break;
    case VIRTIO_STATUS:
        virtio->status = value;
        break;
    }

    return OK;
}

u32 virtio_desc_addr(struct rv32_virtio *virtio)
{
    return (u32) virtio->q_pfn * (u32) virtio->page_size;
}

u32 virtio_disk_read(const struct rv32_virtio *virtio, u32 addr)
{
    return virtio->disk[addr];
}

void virtio_disk_write(const struct rv32_virtio *virtio, u32 addr, u32 value)
{
    virtio->disk[addr] = (u8) value;
}

u32 virtio_new_id(struct rv32_virtio *virtio)
{
    return ++(virtio->id);
}

bool virtio_is_interrupting(struct rv32_virtio *virtio)
{
    if (virtio->q_notify != -1) {
        virtio->q_notify = -1;
        return true;
    }
    return false;
}

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

exception_t read_bus(struct rv32_bus *bus, u32 addr, u32 size, u32 *result)
{
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

exception_t mmu_translate(struct rv32_core *core,
                          u32 addr,
                          exception_t e,
                          u32 *result)
{
    if (!core->enable_paging) {
        *result = addr;
        return OK;
    }

    u32 vpn[] = {
        (addr >> 12) & 0x3ff,  // 10bits
        (addr >> 22) & 0x3ff,  // 10bits
    };
    int level = sizeof(vpn) / sizeof(vpn[0]) - 1;
    u32 pt = core->pagetable;
    u32 pte;

#define PTE_SIZE 4

    while (1) {
        exception_t except =
            read_bus(core->bus, pt + vpn[level] * PTE_SIZE, 32, &pte);
        if (except != OK)
            return except;
        bool v = pte & 1;
        bool r = (pte >> 1) & 0x1;
        bool w = (pte >> 2) & 0x1;
        bool x = (pte >> 3) & 0x1;

        if (!v || (!r && w))
            return e;

        if (r || x)
            break;

        /* 10bits of flags */
        pt = ((pte >> 10) & 0x0fffffff) * PAGE_SIZE;
        if (--level < 0)
            return e;
    }

    u32 ppn[] = {
        (pte >> 10) & 0xfff,
        (pte >> 20) & 0xfff,
    };

    u32 offset = addr & 0xfff;
    switch (level) {
    case 0:
        *result = (((pte >> 10) & 0x0fffffff) << 12) | offset;
        return OK;
    case 1:
        *result = (ppn[1] << 22) | (ppn[0] << 12) | offset;
        return OK;
    default:
        return e;
    }
}

exception_t core_read_bus(struct rv32_core *core,
                          u32 addr,
                          u32 size,
                          u32 *result)
{
    u32 pa;
    exception_t e = mmu_translate(core, addr, LOAD_PAGE_FAULT, &pa);
    if (e != OK)
        return e;

    return read_bus(core->bus, pa, size, result);
}

exception_t core_write_bus(struct rv32_core *core,
                           u32 addr,
                           u32 size,
                           u32 value)
{
    u32 pa;
    exception_t e = mmu_translate(core, addr, LOAD_PAGE_FAULT, &pa);
    if (e != OK)
        return e;

    return write_bus(core->bus, pa, size, value);
}

void bus_disk_access(struct rv32_bus *bus)
{
    u32 desc_addr = virtio_desc_addr(bus->virtio);
    u32 avail_addr = desc_addr + 0x40, used_addr = desc_addr + 4096;

    u32 offset;
    if (read_bus(bus, avail_addr + 1, 16, &offset) != OK)
        pr_err("read offset");

    u32 idx;
    if (read_bus(bus, avail_addr + (offset % VIRTIO_DESC_NUM) + 2, 16, &idx) !=
        OK)
        pr_err("read index");

    u32 desc_addr0 = desc_addr + VIRTIO_VRING_DESC_SIZE * idx;
    u32 addr0;
    if (read_bus(bus, desc_addr0, 32, &addr0) != OK)
        pr_err("read address field in descriptor");

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

    u32 blk_sector;
    if (read_bus(bus, addr0 + 8, 32, &blk_sector) != OK)
        pr_err("read sector field in virtio_blk_outhdr");

    if (!(flags1 & 2)) {
        /* Read RAM data and write it to a disk directly (DMA). */
        for (u32 i = 0; i < len1; i++) {
            u32 data;
            if (read_bus(bus, addr1 + i, 8, &data) != OK)
                pr_err("read from RAM");
            virtio_disk_write(bus->virtio, blk_sector * 512 + i, data);
        }
    } else {
        /* Read Disk data and write it to a RAM directly (DMA). */
        for (u32 i = 0; i < len1; i++) {
            u32 data = virtio_disk_read(bus->virtio, blk_sector * 512 + i);
            if (write_bus(bus, addr1 + i, 8, data) != OK)
                pr_err("write to RAM");
        }
    }

    u32 new_id = virtio_new_id(bus->virtio);
    if (write_bus(bus, used_addr + 2, 16, new_id % 8) != OK)
        pr_err("write to RAM");
}

bool uart_is_interrupting(struct rv32_uart *uart)
{
    pthread_mutex_lock(&uart->lock);
    bool interrupting = uart->interrupting;
    uart->interrupting = false;
    pthread_mutex_unlock(&uart->lock);

    return interrupting;
}

void *uart_thread_func(void *priv)
{
    struct rv32_uart *uart = (struct rv32_uart *) priv;

    while (1) {
        struct pollfd pfd = {0, POLLIN, 0};
        poll(&pfd, 1, 0);
        if (!(pfd.revents & POLLIN))
            continue;

        char c;
        /* An error or EOF */
        if (read(STDIN_FILENO, &c, 1) <= 0)
            continue;

        pthread_mutex_lock(&uart->lock);
        while ((uart->data[UART_LSR - UART_BASE] & UART_LSR_RX_EMPTY) == 1)
            pthread_cond_wait(&uart->cond, &uart->lock);

        uart->data[0] = c;
        uart->interrupting = true;
        uart->data[UART_LSR - UART_BASE] |= UART_LSR_RX_EMPTY;
        pthread_mutex_unlock(&uart->lock);
    }

    /* Should not reach here */
    return NULL;
}

struct rv32_uart *uart_init()
{
    struct rv32_uart *uart = malloc(sizeof(struct rv32_uart));

    uart->data[UART_LSR - UART_BASE] |=
        (UART_LSR_TX_EMPTY | UART_LSR_THR_SR_EMPTY);
    pthread_mutex_init(&uart->lock, NULL);
    pthread_cond_init(&uart->cond, NULL);
    pthread_create(&uart->tid, NULL, uart_thread_func, (void *) uart);

    return uart;
}

struct rv32_clint *clint_init()
{
    struct rv32_clint *clint = malloc(sizeof(struct rv32_clint));
    clint->mtimecmp = 0;
    clint->mtime = 0;

    return clint;
}

struct rv32_plic *plic_init()
{
    return malloc(sizeof(struct rv32_plic));
}

struct rv32_virtio *virtio_init(u8 *disk)
{
    struct rv32_virtio *vio = malloc(sizeof(struct rv32_virtio));
    vio->disk = disk;
    vio->q_notify = -1;

    return vio;
}

struct rv32_bus *bus_init()
{
    struct rv32_bus *bus = malloc(sizeof(struct rv32_bus));

    bus->ram = malloc(sizeof(char) * RAM_SIZE);
    bus->uart0 = uart_init();
    bus->clint = clint_init();
    bus->plic = plic_init();
    bus->virtio = virtio_init(NULL);

    return bus;
}

u32 load_elf(struct rv32_bus *bus, char *filename)
{
    FILE *f = fopen(filename, "rb");
    if (!f)
        pr_err("Open Kernel ELF File !");

    fseek(f, 0, SEEK_END);
    size_t fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    u8 *buf = malloc(sizeof(char) * fsize);
    if (fread(buf, fsize, 1, f) != 1)
        pr_err("Read Kernel ELF File !");

    fclose(f);

#if CONFIG_ARCH_TEST
    u32 pc = parse_elf(bus->ram, buf, &bus->sig.start, &bus->sig.end);
#else
    u32 pc = parse_elf(bus->ram, buf);
#endif

    free(buf);
    return pc;
}

u8 *load_disk(char *filename)
{
    FILE *f = fopen(filename, "rb");
    if (!f)
        pr_err("Open Disk IMG !");

    fseek(f, 0, SEEK_END);
    size_t fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    u8 *disk = malloc(sizeof(char) * fsize);
    if (fread(disk, fsize, 1, f) != 1)
        pr_err("Read Disk IMG !");
    fclose(f);

    return disk;
}

struct rv32_core *core_init(int argc, char **argv)
{
    struct rv32_core *core = malloc(sizeof(struct rv32_core));

    core->bus = bus_init();
    core->mode = MACHINE;

    core->pc = load_elf(core->bus, argv[1]);

#ifndef CONFIG_ARCH_TEST
    core->bus->virtio = virtio_init(load_disk(argv[2]));
#endif

    /* Initialize the SP(x2) */
    core->xreg[2] = RAM_BASE + RAM_SIZE;

    return core;
}

exception_t fetch(struct rv32_core *core)
{
    u32 ppc;
    u32 encode;

    exception_t e = mmu_translate(core, core->pc, INSTRUCTION_PAGE_FAULT, &ppc);
    if (e != OK)
        return e;

    core->xreg[0] = 0;

    if (read_bus(core->bus, ppc, 8, &encode) != OK)
        return INSTRUCTION_ACCESS_FAULT;

    if ((encode & 0x3) == 0x3) {
        core->ctx.encode = 0;
        if (read_bus(core->bus, ppc, 32, &core->ctx.instr) != OK)
            return INSTRUCTION_ACCESS_FAULT;
    } else {
        core->ctx.encode = 1;
        if (read_bus(core->bus, ppc, 16, &core->ctx.instr) != OK)
            return INSTRUCTION_ACCESS_FAULT;
    }

    return OK;
}

u32 read_csr(struct rv32_core *core, u16 addr)
{
    if (addr == SIE)
        return core->csr[MIE] & core->csr[MIDELEG];

    return core->csr[addr];
}

#define SATP_SV32 (1 << 31)
void core_update_paging(struct rv32_core *core, u16 csr_addr)
{
    if (csr_addr != SATP)
        return;

    /* rv32 : ppn is 22bits
     * rv64 : ppn is 44bits
     */
    core->pagetable =
        (read_csr(core, SATP) & (((u32) 1 << 22) - 1)) * PAGE_SIZE;
    core->enable_paging = (1 == (read_csr(core, SATP) >> 31));
}

void write_csr(struct rv32_core *core, u16 addr, u32 value)
{
    if (addr == SIE) {
        core->csr[MIE] = (core->csr[MIE] & ~core->csr[MIDELEG]) |
                         (value & core->csr[MIDELEG]);
        return;
    }
    core->csr[addr] = value;
}

typedef enum {
    I_TYPE_LOAD = 0b00000011,
    I_TYPE_FENCE = 0b00001111,
    I_TYPE = 0b00010011,
    U_TYPE_AUIPC = 0b00010111,
    S_TYPE = 0b00100011,
    A_TYPE = 0b00101111,
    R_TYPE = 0b00110011,
    U_TYPE_LUI = 0b00110111,
    B_TYPE = 0b01100011,
    I_TYPE_JARL = 0b01100111,
    J_TYPE = 0b01101111,
    I_TYPE_SYS = 0b01110011,
} op_type;

exception_t execute_32(struct rv32_core *core)
{
    u32 instr = core->ctx.instr;
    u32 opcode = instr & 0x7f;
    u32 rd = (instr >> 7) & 0x1f;
    u32 rs1 = (instr >> 15) & 0x1f;
    u32 rs2 = (instr >> 20) & 0x1f;
    u32 func3 = (instr >> 12) & 0x7;
    u32 func7 = (instr >> 25) & 0x7f;

    exception_t e;

    switch (opcode) {
    case I_TYPE_LOAD: {
        u32 imm = (int) instr >> 20;
        u32 addr = core->xreg[rs1] + imm;
        u32 result = 0;
        switch (func3) {
        case 0x0: /* lb */
            if ((e = core_read_bus(core, addr, 8, &result)) != OK)
                return e;
            core->xreg[rd] = (s8) result;
            break;
        case 0x1: /* lh */
            if ((e = core_read_bus(core, addr, 16, &result)) != OK)
                return e;
            core->xreg[rd] = (s16) result;
            break;
        case 0x2: /* lw */
            if ((e = core_read_bus(core, addr, 32, &result)) != OK)
                return e;
            core->xreg[rd] = (s32) result;
            break;
        case 0x4: /* lbu */
            if ((e = core_read_bus(core, addr, 8, &core->xreg[rd])) != OK)
                return e;
            break;
        case 0x5: /* lhu */
            if ((e = core_read_bus(core, addr, 16, &core->xreg[rd])) != OK)
                return e;
            break;
        case 0x6: /* lwu */
            if ((e = core_read_bus(core, addr, 32, &core->xreg[rd])) != OK)
                return e;
            break;
        default:
            return ILLEGAL_INSTRUCTION;
        }
        break;
    }
    case I_TYPE_FENCE:
        switch (func3) {
        case 0x0: /* fence */
            /* TODO */
            break;
        case 0x1: /* fence.i */
            /* TODO */
            break;
        default:
            return ILLEGAL_INSTRUCTION;
        }
    case I_TYPE: {
        u32 imm = (int) (instr & 0xfff00000) >> 20;
        u32 shamt = imm & 0x3f;  // imm[0:4]
        switch (func3) {
        case 0x0: /* addi */
            core->xreg[rd] = core->xreg[rs1] + imm;
            break;
        case 0x1: /* slli */
            core->xreg[rd] = core->xreg[rs1] << shamt;
            break;
        case 0x2: /* slti */
            core->xreg[rd] = ((s32) core->xreg[rs1] < (s32) imm) ? 1 : 0;
            break;
        case 0x3: /* sltiu */
            core->xreg[rd] = (core->xreg[rs1] < imm) ? 1 : 0;
            break;
        case 0x4: /* xori */
            core->xreg[rd] = core->xreg[rs1] ^ imm;
            break;
        case 0x5:
            switch (func7) {
            case 0x0: /* srli */
                core->xreg[rd] = core->xreg[rs1] >> shamt;
                break;
            case 0x20: /* srai */
                core->xreg[rd] = (s32) core->xreg[rs1] >> shamt;
                break;
            default:
                return ILLEGAL_INSTRUCTION;
            }
            break;
        case 0x6: /* ori */
            core->xreg[rd] = core->xreg[rs1] | imm;
            break;
        case 0x7: /* andi */
            core->xreg[rd] = core->xreg[rs1] & imm;
            break;
        default:
            return ILLEGAL_INSTRUCTION;
        }
        break;
    }
    case U_TYPE_AUIPC: { /* auipc */
        u32 imm = (s32)(instr & 0xfffff000);
        core->xreg[rd] = core->pc + imm - 4;
        break;
    }
    case S_TYPE: {
        u32 imm =
            (u32)((s32)(instr & 0xfe000000) >> 20) | ((instr >> 7) & 0x1f);
        u32 addr = core->xreg[rs1] + imm;
        switch (func3) {
        case 0x0: /* sb */
            if ((e = core_write_bus(core, addr, 8, core->xreg[rs2])) != OK)
                return e;
            break;
        case 0x1: /* sh */
            if ((e = core_write_bus(core, addr, 16, core->xreg[rs2])) != OK)
                return e;
            break;
        case 0x2: /* sw */
            if ((e = core_write_bus(core, addr, 32, core->xreg[rs2])) != OK)
                return e;
            break;
        default:
            return ILLEGAL_INSTRUCTION;
        }
        break;
    }
    case A_TYPE: {
        u32 func5 = (func7 & 0x7c) >> 2;
        if (func3 == 0x2 && func5 == 0x0) { /* amoadd.w */
            u32 tmp = 0;
            if ((e = core_read_bus(core, core->xreg[rs1], 32, &tmp)) != OK)
                return e;
            if ((e = core_write_bus(core, core->xreg[rs1], 32,
                                    tmp + core->xreg[rs2])) != OK)
                return e;
            core->xreg[rd] = (int) tmp;
        } else if (func3 == 0x2 && func5 == 0x1) { /* amoswap.w */
            u32 tmp = 0;
            if ((e = core_read_bus(core, core->xreg[rs1], 32, &tmp)) != OK)
                return e;
            if ((e = core_write_bus(core, core->xreg[rs1], 32,
                                    core->xreg[rs2])) != OK)
                return e;
            core->xreg[rd] = (int) tmp;
        } else {
            return ILLEGAL_INSTRUCTION;
        }
        break;
    }
    case R_TYPE: {
        u32 shamt = core->xreg[rs2] & 0x3f;
        if (func3 == 0x0 && func7 == 0x00) { /* add */
            core->xreg[rd] = core->xreg[rs1] + core->xreg[rs2];
        } else if (func3 == 0x0 && func7 == 0x01) { /* mul */
            core->xreg[rd] = (s32) core->xreg[rs1] * (s32) core->xreg[rs2];
        } else if (func3 == 0x0 && func7 == 0x20) { /* sub */
            core->xreg[rd] = core->xreg[rs1] - core->xreg[rs2];
        } else if (func3 == 0x1 && func7 == 0x00) { /* sll */
            core->xreg[rd] = core->xreg[rs1] << shamt;
        } else if (func3 == 0x1 && func7 == 0x01) { /* mulh */
            long tmp =
                (long) (s32) core->xreg[rs1] * (long) (s32) core->xreg[rs2];
            core->xreg[rd] = tmp >> 32;
        } else if (func3 == 0x2 && func7 == 0x00) { /* slt */
            core->xreg[rd] =
                ((s32) core->xreg[rs1] < (s32) core->xreg[rs2]) ? 1 : 0;
        } else if (func3 == 0x2 && func7 == 0x01) { /* mulhsu */
            long tmp =
                (long) (s32) core->xreg[rs1] * (unsigned long) core->xreg[rs2];
            core->xreg[rd] = tmp >> 32;
        } else if (func3 == 0x3 && func7 == 0x00) { /* sltu */
            core->xreg[rd] = !!(core->xreg[rs1] < core->xreg[rs2]);
        } else if (func3 == 0x3 && func7 == 0x01) { /* mulhu */
            unsigned long tmp = (unsigned long) core->xreg[rs1] *
                                (unsigned long) core->xreg[rs2];
            core->xreg[rd] = tmp >> 32;
        } else if (func3 == 0x4 && func7 == 0x00) { /* xor */
            core->xreg[rd] = core->xreg[rs1] ^ core->xreg[rs2];
        } else if (func3 == 0x4 && func7 == 0x01) { /* div */
            s32 dividend = (s32) core->xreg[rs1];
            s32 divisor = (s32) core->xreg[rs2];
            if (!divisor)
                core->xreg[rd] = -1;
            else
                core->xreg[rd] = dividend / divisor;
        } else if (func3 == 0x5 && func7 == 0x00) { /* srl */
            core->xreg[rd] = core->xreg[rs1] >> shamt;
        } else if (func3 == 0x5 && func7 == 0x01) { /* divu */
            u32 dividend = core->xreg[rs1];
            u32 divisor = core->xreg[rs2];
            if (!divisor)
                core->xreg[rd] = -1;
            else
                core->xreg[rd] = dividend / divisor;
        } else if (func3 == 0x5 && func7 == 0x20) { /* sra */
            core->xreg[rd] = (s32) core->xreg[rs1] >> shamt;
        } else if (func3 == 0x6 && func7 == 0x00) { /* or */
            core->xreg[rd] = core->xreg[rs1] | core->xreg[rs2];
        } else if (func3 == 0x6 && func7 == 0x01) { /* rem */
            core->xreg[rd] = (s32) core->xreg[rs1] % (s32) core->xreg[rs2];
        } else if (func3 == 0x7 && func7 == 0x00) { /* and */
            core->xreg[rd] = core->xreg[rs1] & core->xreg[rs2];
        } else if (func3 == 0x7 && func7 == 0x01) { /* remu */
            core->xreg[rd] = core->xreg[rs1] % core->xreg[rs2];
        } else {
            return ILLEGAL_INSTRUCTION;
        }
        break;
    }
    case U_TYPE_LUI: /* lui */
        core->xreg[rd] = (s32)(instr & 0xfffff000);
        break;
    case B_TYPE: {
        u32 imm = (u32)((s32)(instr & 0x80000000) >> 19) |
                  ((instr & 0x80) << 4) | ((instr >> 20) & 0x7e0) |
                  ((instr >> 7) & 0x1e);
        switch (func3) {
        case 0x0: /* beq */
            if (core->xreg[rs1] == core->xreg[rs2])
                core->pc += imm - 4;
            break;
        case 0x1: /* bne */
            if (core->xreg[rs1] != core->xreg[rs2])
                core->pc += imm - 4;
            break;
        case 0x4: /* blt */
            if ((s32) core->xreg[rs1] < (s32) core->xreg[rs2])
                core->pc += imm - 4;
            break;
        case 0x5: /* bge */
            if ((s32) core->xreg[rs1] >= (s32) core->xreg[rs2])
                core->pc += imm - 4;
            break;
        case 0x6: /* bltu */
            if (core->xreg[rs1] < core->xreg[rs2])
                core->pc += imm - 4;
            break;
        case 0x7: /* bgeu */
            if (core->xreg[rs1] >= core->xreg[rs2])
                core->pc += imm - 4;
            break;
        default:
            return ILLEGAL_INSTRUCTION;
        }
        break;
    }
    case I_TYPE_JARL: { /* jalr */
        u32 tmp = core->pc;
        u32 imm = (s32)(instr & 0xfff00000) >> 20;
        core->pc = (core->xreg[rs1] + imm) & ~1;
        core->xreg[rd] = tmp;
        break;
    }
    case J_TYPE: { /* jal */
        core->xreg[rd] = core->pc;
        u32 imm = (u32)((s32)(instr & 0x80000000) >> 11) | (instr & 0xff000) |
                  ((instr >> 9) & 0x800) | ((instr >> 20) & 0x7fe);
        core->pc += imm - 4;
        break;
    }
    case I_TYPE_SYS: {
        u16 addr = (instr & 0xfff00000) >> 20;
        switch (func3) {
        case 0x0:
            if (rs2 == 0x0 && func7 == 0x0) { /* ecall */
                switch (core->mode) {
                case USER:
                case SUPERVISOR:
                case MACHINE:
                    return 8 + core->mode;
                }
            } else if (rs2 == 0x1 && func7 == 0x0) { /* ebreak */
                return BREAKPOINT;
            } else if (rs2 == 0x2 && func7 == 0x8) { /* sret */
                core->pc = read_csr(core, SEPC);
                core->mode =
                    ((read_csr(core, SSTATUS) >> 8) & 1) ? SUPERVISOR : USER;
                write_csr(core, SSTATUS,
                          ((read_csr(core, SSTATUS) >> 5) & 1)
                              ? read_csr(core, SSTATUS) | (1 << 1)
                              : read_csr(core, SSTATUS) & ~(1 << 1));
                write_csr(core, SSTATUS, read_csr(core, SSTATUS) | (1 << 5));
                write_csr(core, SSTATUS, read_csr(core, SSTATUS) & ~(1 << 8));
            } else if (rs2 == 0x2 && func7 == 0x18) { /* mret */
                core->pc = read_csr(core, MEPC);
                u32 mpp = (read_csr(core, MSTATUS) >> 11) & 3;
                core->mode =
                    ((mpp == 2) ? MACHINE : (mpp == 1 ? SUPERVISOR : USER));
                write_csr(core, MSTATUS,
                          ((read_csr(core, MSTATUS) >> 7) & 1)
                              ? read_csr(core, MSTATUS) | (MSTATUS_MIE)
                              : read_csr(core, MSTATUS) & ~(MSTATUS_MIE));
                write_csr(core, MSTATUS,
                          read_csr(core, MSTATUS) | (MSTATUS_MPIE));
                write_csr(core, MSTATUS, read_csr(core, MSTATUS) & ~(3 << 11));
            }
            break;
        case 0x1: { /* csrrw */
            u32 tmp = read_csr(core, addr);
            write_csr(core, addr, core->xreg[rs1]);
            core->xreg[rd] = tmp;
            core_update_paging(core, addr);
            break;
        }
        case 0x2: { /* csrrs */
            u32 tmp = read_csr(core, addr);
            write_csr(core, addr, tmp | core->xreg[rs1]);
            core->xreg[rd] = tmp;
            core_update_paging(core, addr);
            break;
        }
        case 0x3: { /* csrrc */
            u32 tmp = read_csr(core, addr);
            write_csr(core, addr, tmp & ~core->xreg[rs1]);
            core->xreg[rd] = tmp;
            core_update_paging(core, addr);
            break;
        }
        case 0x5: { /* csrrwi */
            core->xreg[rd] = read_csr(core, addr);
            write_csr(core, addr, rs1);
            core_update_paging(core, addr);
            break;
        }
        case 0x6: { /* csrrsi */
            u32 tmp = read_csr(core, addr);
            write_csr(core, addr, tmp | rs1);
            core->xreg[rd] = tmp;
            core_update_paging(core, addr);
            break;
        }
        case 0x7: { /* csrrci */
            u32 tmp = read_csr(core, addr);
            write_csr(core, addr, tmp | ~rs1);
            core->xreg[rd] = tmp;
            core_update_paging(core, addr);
            break;
        }
        default:
            return ILLEGAL_INSTRUCTION;
        }
        break;
    }
    default:
        return ILLEGAL_INSTRUCTION;
    };

    return OK;
}
exception_t execute_16(struct rv32_core *core)
{
    u16 instr = (u16) core->ctx.instr;
    u8 opcode = instr & 0x3;
    u8 func3 = (instr >> 13) & 0x7;
    u8 func4 = (instr >> 12) & 0xf;
    u8 func6 = (instr >> 10) & 0x3f;
    u8 func8 = (func6 << 2) | ((instr >> 5) & 0x3);

    exception_t e;

    switch (opcode) {
    case 0x0: {
        u32 result = 0;
        u32 addr = 0;
        u8 offset = 0;
        u8 rd_ = ((instr >> 2) & 0x7) + 8;   // dest
        u8 rs2_ = ((instr >> 2) & 0x7) + 8;  // src
        u8 rs1_ = ((instr >> 7) & 0x7) + 8;  // base

        switch (func3) {
        case 0x0: { /* c.addi4spn */
            u32 imm = ((instr >> 5) & 0x1) << 3 | ((instr >> 6) & 0x1) << 2 |
                      ((instr >> 7) & 0xf) << 6 | ((instr >> 11) & 0x3) << 4;
            if (imm != 0)
                core->xreg[rd_] = core->xreg[2] + imm;
        } break;
        case 0x2: /* c.lw */
            offset = ((instr >> 5) & 0x1) << 6 | ((instr >> 6) & 0x1) << 2 |
                     ((instr >> 10) & 0x7) << 3;
            addr = core->xreg[rs1_] + offset;

            if ((e = core_read_bus(core, addr, 32, &result)) != OK)
                return e;
            core->xreg[rd_] = (s32) result;
            break;
        case 0x6: /* c.sw */
            offset = ((instr >> 5) & 0x1) << 6 | ((instr >> 6) & 0x1) << 2 |
                     ((instr >> 10) & 0x7) << 3;
            addr = core->xreg[rs1_] + offset;

            if ((e = core_write_bus(core, addr, 32, core->xreg[rs2_])) != OK)
                return e;

            break;
        default:
            return ILLEGAL_INSTRUCTION;
        }
    } break;
    case 0x1: {
        u8 rs2_ = ((instr >> 2) & 0x7) + 8;  // src
        u8 rs1_ = ((instr >> 7) & 0x7) + 8;  // dest
        u8 rd_ = ((instr >> 7) & 0x7) + 8;   // dest
        u8 rd = ((instr >> 7) & 0x1f);       // dest
        u8 func2 = (instr >> 10) & 0x3;
        u32 shamt = ((instr >> 12) & 0x1) << 5 | ((instr >> 2) & 0x1f);

        if (func3 == 0x4 && func2 == 0x0) { /* c.srli */
            core->xreg[rd_] >>= shamt;
        } else if (func3 == 0x4 && func2 == 0x1) { /* c.srai */
            core->xreg[rd_] = (s32) core->xreg[rd_] >> shamt;
        } else if (func3 == 0x0 && rd != 0) { /* c.addi */
            s32 imm = ((instr >> 12) & 0x1) << 5 | ((instr >> 2) & 0x1f);
            // sign-extended 6-bit immediate
            imm |= (imm & 0x20) ? 0xffffffc0 : 0;
            if (imm != 0)
                core->xreg[rd] = (u32)((s32) core->xreg[rd] + imm);
        } else if (func3 == 0x4 && func2 == 0x2) { /* c.andi */
            s32 imm = ((instr >> 12) & 0x1) << 5 | ((instr >> 2) & 0x1f);
            // sign-extended 6-bit immediate
            imm |= (imm & 0x20) ? 0xffffffc0 : 0;
            core->xreg[rd_] = (s32) core->xreg[rd_] & imm;
        } else if (func3 == 0x3) {
            if (rd != 0 && rd != 2) { /* c.lui */
                s32 imm = ((instr >> 2) & 0x1f) << 12 | ((instr >> 12) & 0x1)
                                                            << 17;
                imm |= (imm & 0x20000) ? 0xffffc0000 : 0;
                core->xreg[rd] = imm;
            } else if (rd == 2) { /* c.addi16sp */
                s32 imm = ((instr >> 12) & 0x1) << 9 |
                          ((instr >> 2) & 0x1) << 5 |
                          ((instr >> 3) & 0x3) << 7 |
                          ((instr >> 5) & 0x1) << 6 | ((instr >> 6) & 0x1) << 4;
                imm |= (imm & 0x200) ? 0xffffffc00 : 0;
                if (imm != 0)
                    core->xreg[2] = (u32)((s32) core->xreg[2] + imm);
            }
        } else if (func3 == 0x5) { /* c.j */
            u32 offset =
                ((instr >> 2) & 0x1) << 5 | ((instr >> 3) & 0x7) << 1 |
                ((instr >> 6) & 0x1) << 7 | ((instr >> 7) & 0x1) << 6 |
                ((instr >> 8) & 0x1) << 10 | ((instr >> 9) & 0x3) << 8 |
                ((instr >> 11) & 0x1) << 4 | ((instr >> 12) & 0x1) << 11;
            offset |= (offset & 0x800) ? 0xfffff000 : 0;
            core->pc += (offset - 2);
        } else if (func3 == 0x1) { /* c.jal */
            u32 offset =
                ((instr >> 2) & 0x1) << 5 | ((instr >> 3) & 0x7) << 1 |
                ((instr >> 6) & 0x1) << 7 | ((instr >> 7) & 0x1) << 6 |
                ((instr >> 8) & 0x1) << 10 | ((instr >> 9) & 0x3) << 8 |
                ((instr >> 11) & 0x1) << 4 | ((instr >> 12) & 0x1) << 11;
            offset |= (offset & 0x800) ? 0xfffff000 : 0;
            core->xreg[1] = core->pc;
            core->pc += (offset - 2);
        } else if (func3 == 0x6) { /* c.beqz */
            u32 offset = ((instr >> 2) & 0x1) << 5 | ((instr >> 3) & 0x3) << 1 |
                         ((instr >> 5) & 0x3) << 6 |
                         ((instr >> 10) & 0x3) << 3 |
                         ((instr >> 12) & 0x1) << 8;
            offset |= (offset & 0x100) ? 0xfffffE00 : 0;
            if (core->xreg[rs1_] == 0)
                core->pc += (offset - 2);
        } else if (func3 == 0x7) { /* c.bnqz */
            u32 offset = ((instr >> 2) & 0x1) << 5 | ((instr >> 3) & 0x3) << 1 |
                         ((instr >> 5) & 0x3) << 6 |
                         ((instr >> 10) & 0x3) << 3 |
                         ((instr >> 12) & 0x1) << 8;
            offset |= (offset & 0x100) ? 0xfffffE00 : 0;
            if (core->xreg[rs1_] != 0)
                core->pc += (offset - 2);
        } else if (func3 == 0x2) { /* c.li */
            s32 imm = ((instr >> 12) & 0x1) << 5 | ((instr >> 2) & 0x1f);
            imm |= (imm & 0x20) ? 0xffffffc0 : 0;
            core->xreg[rd] = imm;
        } else if (func3 == 0x0) { /* c.nop */
            return OK;
        } else {
            switch (func8) {
            case 0x8f: /* c.and */
                core->xreg[rd_] &= core->xreg[rs2_];
                break;
            case 0x8e: /* c.or */
                core->xreg[rd_] |= core->xreg[rs2_];
                break;
            case 0x8d: /* c.xor */
                core->xreg[rd_] ^= core->xreg[rs2_];
                break;
            case 0x8c: /* c.sub */
                core->xreg[rd_] -= core->xreg[rs2_];
                break;

            default:
                return ILLEGAL_INSTRUCTION;
            }
        }

    } break;
    case 0x2: {
        u32 rs2 = ((instr >> 2) & 0x1f);
        u32 rs1 = ((instr >> 7) & 0x1f);
        u32 rd = ((instr >> 7) & 0x1f);
        u32 offset = 0;
        u32 addr = 0;
        u32 shamt = ((instr >> 12) & 0x1) << 5 | ((instr >> 2) & 0x1f);

        if ((func3 == 0x4 && func4 == 0x9) && rs2 != 0) { /* c.add */
            core->xreg[rd] =
                (s32)((u32) core->xreg[rd] + (u32) core->xreg[rs2]);
        } else if (func4 == 0x9 && rs2 == 0) {
            if (rs1 == 0) { /* c.ebreak */
                core->pc += 2;
                return BREAKPOINT;
            } else { /* c.jalr */
                u32 prev_pc = core->pc;
                core->pc = core->xreg[rs1];
                core->xreg[1] = prev_pc;
            }
        } else if (func4 == 0x8 && rs1 != 0 && rs2 == 0) { /* c.jr */
            core->pc = core->xreg[rs1];
        } else if ((func3 == 0x4 && func4 == 0x8) && rs2 != 0) { /* c.mv */
            core->xreg[rd] = core->xreg[rs2];
        } else if (func3 == 0x0) { /* c.slli */
            core->xreg[rd] = core->xreg[rs1] << shamt;
        } else if (func3 == 0x2) { /* c. lwsp */
            offset = ((instr >> 2) & 0x3) << 6 | ((instr >> 4) & 0x7) << 2 |
                     ((instr >> 12) & 0x1) << 5;
            addr = core->xreg[2] + offset;  // sp
            if ((e = core_read_bus(core, addr, 32, &core->xreg[rd])) != OK)
                return e;
        } else if (func3 == 0x6) { /* c.swsp */
            offset = ((instr >> 7) & 0x3) << 6 | ((instr >> 9) & 0xf) << 2;
            addr = core->xreg[2] + offset;  // sp
            if ((e = core_write_bus(core, addr, 32, core->xreg[rs2])) != OK)
                return e;
        } else {
            return ILLEGAL_INSTRUCTION;
        }
    } break;
    default:
        return ILLEGAL_INSTRUCTION;
    };

    return OK;
}

exception_t execute(struct rv32_core *core)
{
    if (!core->ctx.encode) {
        core->pc += 4;
        return execute_32(core);
    } else {
        core->pc += 2;
        return execute_16(core);
    }

    /* never be here */
    return OK;
}


void trap_handler(struct rv32_core *core,
                  const exception_t e,
                  const interrupt_t intr)
{
    u32 exception_pc = core->pc - 4;
    core_mode_t prev_mode = core->mode;
    bool is_interrupt = (intr != NONE);
    u32 cause = e;

    if (is_interrupt)
        cause = (0x80000000 | intr);

    if (prev_mode <= SUPERVISOR &&
        (((read_csr(core, MEDELEG) >> (u32) cause) & 1) != 0)) {
        core->mode = SUPERVISOR;
        /* Set PC to handler routine address */
        if (is_interrupt) {
            u32 vec = (read_csr(core, STVEC) & 1) ? 4 * cause : 0;
            core->pc = (read_csr(core, STVEC) & ~1) + vec;
        } else
            core->pc = read_csr(core, STVEC);
        write_csr(core, SEPC, exception_pc & ~1);
        write_csr(core, SCAUSE, cause);
        write_csr(core, STVAL, 0);

        write_csr(core, SSTATUS,
                  ((read_csr(core, SSTATUS) >> 1) & 1)
                      ? read_csr(core, SSTATUS) | (1 << 5)
                      : read_csr(core, SSTATUS) & ~(1 << 5));
        write_csr(core, SSTATUS, read_csr(core, SSTATUS) & ~(1 << 1));

        if (prev_mode == USER)
            write_csr(core, SSTATUS, read_csr(core, SSTATUS) & ~(1 << 8));
        else
            write_csr(core, SSTATUS, read_csr(core, SSTATUS) | (1 << 8));
    } else {
        core->mode = MACHINE;

        /* Set PC to handler routine address */
        if (is_interrupt) {
            u32 vec = (read_csr(core, MTVEC) & 1) ? 4 * cause : 0;
            core->pc = (read_csr(core, MTVEC) & ~1) + vec;
        } else
            core->pc = read_csr(core, MTVEC) & ~1;

        /* Store the PC which got the exception to MEPC */
        write_csr(core, MEPC, exception_pc & ~1);

        /* Set the trap reason to MCAUSE */
        write_csr(core, MCAUSE, cause);

        /* Set MTVAL to 0 because this is an interrupt
         * (access illegal and illegal Instruction need to update MTVAL)
         */
        write_csr(core, MTVAL, 0);

        write_csr(core, MSTATUS,
                  ((read_csr(core, MSTATUS) >> 3) & 1)
                      ? read_csr(core, MSTATUS) | (MSTATUS_MPIE)
                      : read_csr(core, MSTATUS) & ~(MSTATUS_MPIE));
        write_csr(core, MSTATUS, read_csr(core, MSTATUS) & ~(MSTATUS_MIE));
        write_csr(core, MSTATUS, read_csr(core, MSTATUS) & ~(3 << 11));
    }
}

enum {
    VIRTIO_IRQ = 1,
    UART_IRQ = 10,
};

interrupt_t check_pending_interrupt(struct rv32_core *core)
{
    if (core->mode == MACHINE && ((read_csr(core, MSTATUS) >> 3) & 1) == 0)
        return NONE;
    if (core->mode == SUPERVISOR && ((read_csr(core, SSTATUS) >> 1) & 1) == 0)
        return NONE;

    do {
        u32 irq;
        if (uart_is_interrupting(core->bus->uart0)) {
            irq = UART_IRQ;
        } else if (virtio_is_interrupting(core->bus->virtio)) {
            bus_disk_access(core->bus);
            irq = VIRTIO_IRQ;
        } else
            break;

        write_bus(core->bus, PLIC_CLAIM, 32, irq);
        write_csr(core, MIP, read_csr(core, MIP) | MIP_SEIP);
    } while (0);

    u32 pending = read_csr(core, MIE) & read_csr(core, MIP);

    if (pending & MIP_MEIP) {
        write_csr(core, MIP, read_csr(core, MIP) & ~MIP_MEIP);
        return MACHINE_EXTERNAL_INTERRUPT;
    }

    if (pending & MIP_MSIP) {
        write_csr(core, MIP, read_csr(core, MIP) & ~MIP_MSIP);
        return MACHINE_SOFTWARE_INTERRUPT;
    }

    /* Machine Timer Interrupt Pending */
    if (pending & MIP_MTIP) {
        /* Clear Timer Interrupt Pending flag */
        write_csr(core, MIP, read_csr(core, MIP) & ~MIP_MTIP);
        return MACHINE_TIMER_INTERRUPT;
    }

    if (pending && MIP_SEIP) {
        write_csr(core, MIP, read_csr(core, MIP) & ~MIP_SEIP);
        return SUPERVISOR_EXTERNAL_INTERRUPT;
    }

    if (pending & MIP_SSIP) {
        write_csr(core, MIP, read_csr(core, MIP) & ~MIP_SSIP);
        return SUPERVISOR_SOFTWARE_INTERRUPT;
    }

    if (pending & MIP_STIP) {
        write_csr(core, MIP, read_csr(core, MIP) & ~MIP_STIP);
        return SUPERVISOR_TIMER_INTERRUPT;
    }

    return NONE;
}

void tick(struct rv32_core *core)
{
    struct rv32_clint *clint = core->bus->clint;

    // clint->mtime++;

    if ((clint->mtimecmp > 0) & (clint->mtime >= clint->mtimecmp)) {
        write_csr(core, MIP, MIP_MTIP);
        /* TODO: This is a workaround */
        clint->mtimecmp *= 2;
    }
}


int emu(int argc, char **argv)
{
    struct rv32_core *core;
    exception_t e;
    core = core_init(argc, argv);

    while (1) {
        // tick(core);

        if ((e = fetch(core)) != OK) {
            break;
        }

        if ((e = execute(core)) != OK) {
            trap_handler(core, e, NONE);
            if (exception_is_fatal(e))
                break;
        }

        interrupt_t intr;
        if ((intr = check_pending_interrupt(core)) != NONE) {
            trap_handler(core, OK, intr);
        }
    }

#if CONFIG_ARCH_TEST
    if (opt_arch_test) {
        FILE *f = fopen(signature_out_file, "w");
        if (!f)
            return 0;

        u32 start = core->bus->sig.start;
        u32 end = core->bus->sig.end;

        for (int i = start; i < end; i += 4) {
            u32 val = 0;
            read_ram(core->bus->ram, i, 32, &val);
            fprintf(f, "%08x\n", (val & 0xffffffff));
        }
        fclose(f);
    }
#endif

    return 0;
}

int main(int argc, char **argv)
{
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    if (argc < 2) {
        printf("Usage: %s <filename>\n", argv[0]);
        return -1;
    }

#if CONFIG_ARCH_TEST
    for (int i = 0; i < argc; i++) {
        if (!strcmp(argv[i], "--arch-test")) {
            opt_arch_test = true;
            strncpy(signature_out_file, argv[i + 1], 255);
            signature_out_file[255] = '\0';
            break;
        }
    }
#endif

    return emu(argc, argv);
}
