#ifndef LINK_UART_H
#define LINK_UART_H

#include <gba_types.h>

/* Compact wrapper around SIO's asynchronous UART mode (SIO_MODE_UART):
 * 115200 8N1, RX/TX enabled. Compatible with LinkUART from
 * gba-link-connection but without C++.
 */

void uart_init(void);

/* Sends a byte (blocking: waits until TX is not full). */
void uart_send_byte(u8 b);
void uart_send_bytes(const u8* buf, u32 len);

/* Receives a byte. Returns -1 if the VBlank-frame timeout elapses.
 * Waits using VBlankIntrWait (no CPU burn) — useful when you can wait
 * a long time, but caps throughput at 1 byte/frame (60 B/s). */
int  uart_recv_byte_timeout(u32 vblank_timeout);

/* Same but with busy-spin (no VBlankIntrWait). Drains at CPU speed
 * (~MB/s), avoiding overflow of the 4-byte RX FIFO when bursts arrive
 * at 115200 baud. Use this when waiting for a byte of an ONGOING stream
 * (recv_n of the payload), not when passively waiting at the start.
 * The `frame_equivalent` parameter is interpreted as approximately
 * 280k spins per frame (16 ms at 16.78 MHz). */
int  uart_recv_byte_busy(u32 frame_equivalent);

/* Non-blocking peek: returns the byte if one is available, -1 if not.
 * Useful in cooperative loops that want to update the UI while waiting
 * for input. */
int  uart_try_recv_byte(void);

/* Drains RX. */
void uart_flush_rx(void);

#endif
