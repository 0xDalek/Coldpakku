#ifndef LINK_UART_H
#define LINK_UART_H

#include <gba_types.h>

/* Wrapper compacto sobre el modo UART asíncrono del SIO (SIO_MODE_UART):
 * 115200 8N1, RX/TX habilitados. Compatible con LinkUART de
 * gba-link-connection pero sin C++.
 */

void uart_init(void);

/* Envía un byte (bloqueante: espera a que TX no esté full). */
void uart_send_byte(u8 b);
void uart_send_bytes(const u8* buf, u32 len);

/* Recibe un byte. Si hay timeout en frames de VBlank, devuelve -1.
 * Espera con VBlankIntrWait (no quema CPU) — útil cuando puedes esperar
 * mucho tiempo, pero limita el throughput a 1 byte/frame (60 B/s). */
int  uart_recv_byte_timeout(u32 vblank_timeout);

/* Igual pero con busy-spin (sin VBlankIntrWait). Drena al ritmo del CPU
 * (~MB/s), evita que el FIFO RX de 4 bytes se desborde cuando llegan
 * bursts a 115200 baud. Usar cuando esperamos un byte de un STREAM en
 * curso (recv_n del payload), no cuando esperamos pasivamente al inicio.
 * El parametro `frame_equivalent` se interpreta como aprox 280k spins
 * por frame (16ms a 16.78MHz). */
int  uart_recv_byte_busy(u32 frame_equivalent);

/* Peek no bloqueante: devuelve el byte si hay uno disponible, -1 si no.
 * Util para loops cooperativos que quieren actualizar UI mientras
 * esperan input. */
int  uart_try_recv_byte(void);

/* Drena RX. */
void uart_flush_rx(void);

#endif
