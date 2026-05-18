#include "protocol.h"
#include "uart.h"

#include <string.h>

/* Busy-spin variant for streaming the payload. The SIO RX FIFO only
 * holds 4 bytes; with `uart_recv_byte_timeout` (1 byte/frame = 60 B/s)
 * it would overflow under bursts at 115200 baud. `uart_recv_byte_busy`
 * drains at CPU pace. */
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

/* wait_ack may wait for a long time (up to 30s between transactions),
 * so we use VBlank-wait to avoid burning CPU. It's only 1 byte. */
int protocol_wait_ack(void) {
    int b = uart_recv_byte_timeout(PROTO_TX_TIMEOUT_FRAMES);
    return b == PROTO_ACK;
}

void protocol_send_sig(const u8 sig[65]) {
    /* SIGSTART before the signature: marker so the host can sync up
     * by discarding residual READYs from the pulse cycle. */
    uart_send_byte(PROTO_SIGSTART);
    uart_send_bytes(sig, 65);
}

void protocol_send_address(const u8 address[20]) {
    uart_send_byte(PROTO_ADDRSTART);
    uart_send_bytes(address, 20);
}

static void put_u32_be(u8 out[4], u32 v) {
    out[0] = (u8)((v >> 24) & 0xFF);
    out[1] = (u8)((v >> 16) & 0xFF);
    out[2] = (u8)((v >>  8) & 0xFF);
    out[3] = (u8)( v        & 0xFF);
}

void protocol_send_policy(u32 chain_id) {
    uart_send_byte(PROTO_POLICYSTART);
    u8 be[4];
    put_u32_be(be, chain_id);
    uart_send_bytes(be, 4);
}

void protocol_send_connect_ok(void) {
    uart_send_byte(PROTO_CONNECT_OK);
}

void protocol_send_reject_chain(u32 expected, u32 got) {
    uart_send_byte(PROTO_REJECT_CHAIN);
    u8 be[4];
    put_u32_be(be, expected);
    uart_send_bytes(be, 4);
    put_u32_be(be, got);
    uart_send_bytes(be, 4);
}

int protocol_recv_opcode(void) {
    /* busy-spin: the host sends the opcode immediately after the ACK
     * and the 4-byte RX FIFO can saturate if we wait for VBlank. */
    return uart_recv_byte_busy(PROTO_TX_TIMEOUT_FRAMES);
}

int protocol_recv_lenprefixed(u8* out_buf, u32 capacity, u32 max_total, u32* out_len) {
    u8 len_be[4];
    if (!recv_n(len_be, 4)) return 0;
    u32 len = ((u32)len_be[0] << 24) | ((u32)len_be[1] << 16)
            | ((u32)len_be[2] << 8)  |  (u32)len_be[3];

    u32 cap = capacity < max_total ? capacity : max_total;
    if (len == 0 || len > cap) return 0;
    if (!recv_n(out_buf, len)) return 0;

    *out_len = len;
    return 1;
}

int protocol_recv_lenprefixed_2b(u8* out_buf, u32 capacity, u32 max_total, u32* out_len) {
    u8 len_be[2];
    if (!recv_n(len_be, 2)) return 0;
    u32 len = ((u32)len_be[0] << 8) | (u32)len_be[1];

    u32 cap = capacity < max_total ? capacity : max_total;
    if (len > cap) return 0;
    if (len > 0 && !recv_n(out_buf, len)) return 0;

    *out_len = len;
    return 1;
}

int protocol_recv_tx_rlp(u8* out_buf, u32 capacity, u32* out_len) {
    int op = protocol_recv_opcode();
    if (op != PROTO_TX_RLP) return 0;
    return protocol_recv_lenprefixed(out_buf, capacity, PROTO_TX_RLP_MAX, out_len);
}
