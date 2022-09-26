#include "uart.h"

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
