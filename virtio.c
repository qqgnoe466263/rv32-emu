#include "virtio.h"

struct rv32_virtio *virtio_init(u8 *disk)
{
    struct rv32_virtio *vio = malloc(sizeof(struct rv32_virtio));
    memset(vio, 0, sizeof(struct rv32_virtio));

    vio->config[1] = 0x00;
    vio->config[2] = 0x01;
    vio->disk = disk;
    vio->q_notify = -1;

    return vio;
}

bool virtio_is_interrupting(struct rv32_virtio *virtio)
{
    if (virtio->q_notify != -1) {
        virtio->isr |= 1;
        virtio->q_notify = -1;
        return true;
    }
    return false;
}

exception_t read_virtio(struct rv32_virtio *virtio,
                        u32 addr,
                        u32 size,
                        u32 *result)
{
    if (addr >= VIRTIO_CONFIG) {
        int index = addr - VIRTIO_CONFIG;
        if (index >= 8)
            return LOAD_ACCESS_FAULT;
        *result = virtio->config[index];
        return OK;
    }

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
        *result = 0;  // 1 << 28;
        break;
    case VIRTIO_DRIVER_FEATURES:
        *result = virtio->driver_features;
        break;
    case VIRTIO_QUEUE_NUM_MAX:
        *result = VIRTIO_DESC_NUM;
        break;
    case VIRTIO_QUEUE_PFN:
        *result = virtio->q_pfn;
        break;
    case VIRTIO_INTERRUPT_STATUS:
        *result = virtio->isr;
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
    if (addr >= VIRTIO_CONFIG) {
        int index = addr - VIRTIO_CONFIG;
        if (index >= 8)
            return LOAD_ACCESS_FAULT;
        virtio->config[index] = (value >> (index * 8)) & 0xff;
        return OK;
    }

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
    case VIRTIO_INTERRUPT_ACK:
        virtio->isr &= ~(value & 0xff);
        break;
    case VIRTIO_STATUS:
        virtio->status = value;
        break;
    }

    return OK;
}
