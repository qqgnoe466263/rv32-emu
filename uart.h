#ifndef _UART_H_
#define _UART_H_

#include <poll.h>
#include <pthread.h>
#include <unistd.h>

#include "common.h"
#include "trap.h"

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

struct rv32_uart *uart_init();
bool uart_is_interrupting(struct rv32_uart *uart);
exception_t read_uart(struct rv32_uart *uart, u32 addr, u32 size, u32 *result);
exception_t write_uart(struct rv32_uart *uart, u32 addr, u32 size, u32 value);

#endif
