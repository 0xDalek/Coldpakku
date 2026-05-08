#include "protocol.h"
#include "uart.h"

#include <string.h>

/* Variante busy-spin para stream payload. El FIFO RX del SIO solo guarda
 * 4 bytes; con `uart_recv_byte_timeout` (1 byte/frame = 60 B/s) se
 * desbordaria con bursts a 115200 baud. `uart_recv_byte_busy` drena al
 * ritmo del CPU. */
static int recv_n(u8* buf, u32 n) {
    for (u32 i = 0; i < n; i++) {
        int b = uart_recv_byte_busy(PROTO_TX_TIMEOUT_FRAMES);
        if (b < 0) return 0;
        buf[i] = (u8)b;
    }
    return 1;
}

void protocol_send_ready(void)  { uart_send_byte(PROTO_READY); }
void protocol_send_cancel(void) { uart_send_byte(PROTO_CANCEL); }
void protocol_send_done(void)   { uart_send_byte(PROTO_DONE); }

/* wait_ack puede esperar mucho (hasta 30s entre transacciones), asi que
 * usamos VBlank-wait para no quemar CPU. Solo es 1 byte. */
int protocol_wait_ack(void) {
    int b = uart_recv_byte_timeout(PROTO_TX_TIMEOUT_FRAMES);
    return b == PROTO_ACK;
}

void protocol_send_sig(const u8 sig[65]) {
    /* SIGSTART antes de la firma: marker para que el host se sincronice
     * descartando READYs residuales del pulse cycle. */
    uart_send_byte(PROTO_SIGSTART);
    uart_send_bytes(sig, 65);
}

int protocol_recv_tx_rlp(u8* out_buf, u32 capacity, u32* out_len) {
    /* Para el primer byte del stream (opcode) tambien usamos busy-spin:
     * tras el ACK, el host empieza a vomitar bytes inmediatamente y nos
     * los puede empezar a meter en el FIFO antes de que volvamos del
     * VBlank. */
    int op = uart_recv_byte_busy(PROTO_TX_TIMEOUT_FRAMES);
    if (op != PROTO_TX_RLP) return 0;

    u8 len_be[4];
    if (!recv_n(len_be, 4)) return 0;
    u32 len = ((u32)len_be[0] << 24) | ((u32)len_be[1] << 16)
            | ((u32)len_be[2] << 8)  |  (u32)len_be[3];

    if (len == 0 || len > capacity || len > PROTO_TX_RLP_MAX) return 0;
    if (!recv_n(out_buf, len)) return 0;

    *out_len = len;
    return 1;
}
