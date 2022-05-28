#ifndef _UART_H_
#define _UART_H_

#include "mem.h"

#define UART0_RHR     (UART0_BASE + 0) // Receive Holding Register (for input bytes)
#define UART0_THR     (UART0_BASE + 0) // Transmit Holding Register (for output bytes)
#define UART0_IER     (UART0_BASE + 1) // Interrupt Enable Register
#define UART0_FCR     (UART0_BASE + 2) // FIFO Control Register
#define UART0_ISR     (UART0_BASE + 2) // Interrupt Status Register
#define UART0_LCR     (UART0_BASE + 3) // Line Control Register

/* LSR (Line Status Register) 
 * (Ref : https://www.lookrs232.com/rs232/lsr.html)
 * Bit 0 (when set) shows data ready, which means that a byte has been received by 
 *       the UART and is at the receiver holding register(RHR) ready to be read.
 * Bit 5 (when set) only shows that transmitter holding register(THR) is empty.
 * Bit 6 (when set) signals that transmitter holding register and the shift register are empty.
 */
#define UART0_LSR               (UART0_BASE + 5) // Line Status Register
#define UART0_LSR_RHR_EMPTY     (1 << 0)
#define UART0_LSR_THR_EMPTY     (1 << 5)
#define UART0_LSR_THR_SR_EMPTY  (1 << 6) 

#endif
