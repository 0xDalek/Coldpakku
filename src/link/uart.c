/*
 * GBA SIO UART mode. Registers:
 *   REG_RCNT   = 0           (no GPIO; let SIOCNT control)
 *   REG_SIOCNT = bits...
 *
 * Relevant SIOCNT bits in UART mode:
 *   bits 0-1 : baud (00=9600, 01=38400, 10=57600, 11=115200)
 *   bit 2    : CTS  (0 = always send)
 *   bit 3    : Parity Control
 *   bit 4    : SI / Send Data Flag (0 = TX not full)
 *   bit 5    : SO / Receive Data Flag (1 = RX empty)
 *   bit 6    : Error Flag
 *   bit 7    : Data Length (1 = 8 bit)
 *   bit 8    : FIFO Enable
 *   bit 9    : Parity Enable
 *   bit 10   : Send Enable
 *   bit 11   : Receive Enable
 *   bits 12  : ?
 *   bit 13   : Mode select (must be 1, 0 = UART → SIO_MODE_UART)
 *   bit 14   : IRQ enable
 *   bit 15   : Mode bit 1
 *
 * SIO_MODE_UART = 0x3000
 */
#include "uart.h"

#include <gba_sio.h>
#include <gba_systemcalls.h>
#include <gba_video.h>

/* libgba/gba_sio.h doesn't define the UART-mode-specific bits; we add
 * them here per the official GBA documentation (gbatek). */
#define SIO_UART_CTS         (1u <<  2)
#define SIO_UART_PARITY_ODD  (1u <<  3)
#define SIO_UART_TX_FULL     (1u <<  4)   /* read-only: 1 = TX full */
#define SIO_UART_RX_EMPTY    (1u <<  5)   /* read-only: 1 = RX empty */
#define SIO_UART_ERROR       (1u <<  6)
#define SIO_UART_8BIT        (1u <<  7)
#define SIO_UART_FIFO        (1u <<  8)
#define SIO_UART_PARITY_EN   (1u <<  9)
#define SIO_UART_TX_ENABLE   (1u << 10)
#define SIO_UART_RX_ENABLE   (1u << 11)
#define SIO_UART_IRQ         (1u << 14)

void uart_init(void) {
    REG_RCNT = R_UART;
    REG_SIOCNT = SIO_UART
               | SIO_115200
               | SIO_UART_RX_ENABLE
               | SIO_UART_TX_ENABLE
               | SIO_UART_8BIT
               | SIO_UART_FIFO;
}

static inline int tx_full(void) {
    return (REG_SIOCNT & SIO_UART_TX_FULL) ? 1 : 0;
}
static inline int rx_empty(void) {
    return (REG_SIOCNT & SIO_UART_RX_EMPTY) ? 1 : 0;
}

void uart_send_byte(u8 b) {
    while (tx_full()) { /* spin */ }
    REG_SIODATA8 = b;
}

void uart_send_bytes(const u8* buf, u32 len) {
    for (u32 i = 0; i < len; i++) uart_send_byte(buf[i]);
}

int uart_recv_byte_timeout(u32 vblank_timeout) {
    u32 frames = 0;
    while (rx_empty()) {
        VBlankIntrWait();
        if (++frames > vblank_timeout) return -1;
    }
    return REG_SIODATA8 & 0xFF;
}

/* Busy-spin without VBlankIntrWait. ~280k iterations per frame (16ms)
 * at 16.78 MHz CPU. Drains the FIFO at CPU speed, much faster than
 * 115200 baud (~11 KB/s), so the 4-byte FIFO never fills up. */
int uart_recv_byte_busy(u32 frame_equivalent) {
    /* Conservative upper cap: ~280k spins/frame. */
    u32 max_spins = frame_equivalent * 280000UL;
    u32 spins = 0;
    while (rx_empty()) {
        if (++spins > max_spins) return -1;
    }
    return REG_SIODATA8 & 0xFF;
}

int uart_try_recv_byte(void) {
    if (rx_empty()) return -1;
    return REG_SIODATA8 & 0xFF;
}

void uart_flush_rx(void) {
    while (!rx_empty()) (void)REG_SIODATA8;
}
