#ifndef _VIRTIO_H_
#define _VIRTIO_H_

#include "common.h"
#include "trap.h"

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
#define VIRTIO_CONFIG (VIRTIO_BASE + 0x100)

struct rv32_virtio {
    u32 id;
    u32 driver_features;
    u32 page_size;
    u32 q_sel;
    u32 q_num;
    u32 q_pfn;
    u32 q_notify;
    u32 isr;
    u32 status;
    u8 config[8];
    u8 *disk;
};

struct rv32_virtio *virtio_init(u8 *disk);
bool virtio_is_interrupting(struct rv32_virtio *virtio);

exception_t read_virtio(struct rv32_virtio *virtio,
                        u32 addr,
                        u32 size,
                        u32 *result);

exception_t write_virtio(struct rv32_virtio *virtio,
                         u32 addr,
                         u32 size,
                         u32 value);

inline u32 virtio_desc_addr(struct rv32_virtio *virtio)
{
    return (u32) virtio->q_pfn * (u32) virtio->page_size;
}

inline u32 virtio_disk_read(const struct rv32_virtio *virtio, u32 addr)
{
    return virtio->disk[addr];
}

inline void virtio_disk_write(const struct rv32_virtio *virtio,
                              u32 addr,
                              u32 value)
{
    virtio->disk[addr] = (u8) value;
}

inline u32 virtio_new_id(struct rv32_virtio *virtio)
{
    return ++(virtio->id);
}

#endif
