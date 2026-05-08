#ifndef LINK_PROTOCOL_H
#define LINK_PROTOCOL_H

#include "../types.h"

/*
 * Protocolo handshake (versión 3 — on-device RLP + TX result):
 *
 *   GBA  → PC : 0xAA              (ready, pulsado cada 0.5s mientras espera)
 *   PC   → GBA: 0xBB              (acknowledge)
 *   PC   → GBA: 0xCD              (tx_rlp opcode)
 *   PC   → GBA: 4B len_be + N bytes RLP serializado
 *               (N hasta PROTO_TX_RLP_MAX = 4096)
 *   GBA parsea, calcula keccak interno, muestra al usuario
 *   GBA  → PC : 0xCE marker SIGSTART  ─ uniquely identifies start of sig
 *   GBA  → PC : 65B firma (r||s||v=0xFE)
 *               o, si user cancela:
 *   GBA  → PC : 0xFF              (cancel, en lugar de la firma)
 *   GBA  → PC : 0xCC              (done)
 *
 *   --- nuevo en v3: feedback de broadcast ---
 *   PC   → GBA: 0xCF              (tx_result opcode, opcional)
 *   PC   → GBA: 1B status         (0x00=BROADCAST_OK, 0x01=BROADCAST_ERR,
 *                                  0x02=NO_BROADCAST  signed only)
 *     si status == 0x00 o 0x02:
 *       PC -> GBA: 32B txhash
 *     si status == 0x01:
 *       PC -> GBA: 1B err_len + err_len bytes UTF-8 (max 64)
 *
 *   El GBA muestra una pantalla "TX BROADCAST" con el hash o el error y
 *   espera A para volver a `awaiting transaction`. Si el host antiguo no
 *   envia TXRESULT, el GBA hace timeout cooperativo (~30s con spinner)
 *   y vuelve solo, sin romper compatibilidad hacia atras.
 *
 *   El marker 0xCE permite al host descartar cualquier 0xAA residual del
 *   pulse cycle (READYs que estaban en transit cuando el GBA recibio el
 *   ACK) y sincronizarse con el inicio real de la firma. Sin el marker,
 *   un READY pendiente se confundiria con el primer byte de la firma y
 *   todo el handshake desincronizaba.
 */

#define PROTO_READY      0xAA
#define PROTO_ACK        0xBB
#define PROTO_TX_RLP     0xCD
#define PROTO_DONE       0xCC
#define PROTO_SIGSTART   0xCE
#define PROTO_TXRESULT   0xCF
#define PROTO_CANCEL     0xFF

/* Status bytes para PROTO_TXRESULT */
#define TXRESULT_BROADCAST_OK   0x00
#define TXRESULT_BROADCAST_ERR  0x01
#define TXRESULT_NO_BROADCAST   0x02

#define TXRESULT_ERRMSG_MAX     64

#define PROTO_TX_TIMEOUT_FRAMES (60 * 30)   /* 30 s a 60 fps */

/* Tope que aceptamos para una tx. EIP-1559 normales caben en <300 bytes;
 * swaps de Uniswap o calls de contrato grandes raramente pasan de 2 KB.
 * 4 KB nos da margen y sigue siendo trivial en EWRAM. */
#define PROTO_TX_RLP_MAX 4096u

/* Recibe el opcode + length-prefixed payload RLP del PC.
 * Escribe los bytes en out_buf y la longitud en *out_len.
 * Devuelve 1 si OK; 0 en timeout, opcode inesperado o longitud > capacity. */
int protocol_recv_tx_rlp(u8* out_buf, u32 capacity, u32* out_len);

/* Envia: byte SIGSTART (0xCE) + 65B sig. El SIGSTART permite al host
 * sincronizarse descartando READYs residuales del pulse cycle previo. */
void protocol_send_sig(const u8 sig[65]);
void protocol_send_cancel(void);
void protocol_send_done(void);

void protocol_send_ready(void);
int  protocol_wait_ack(void);

#endif
