#ifndef UI_CONFIRM_H
#define UI_CONFIRM_H

#include "../types.h"
#include "../crypto/eth_tx.h"

/* Muestra la pantalla de confirmación con todos los campos parseados de la
 * tx (nonce, fees, gas, to en EIP-55, value, data con paginación si es
 * larga). Devuelve 1 si el usuario pulsa A (confirmar), 0 si pulsa B. */
int confirm_tx(const eth_tx* tx);

/* Pregunta sí/no genérica. */
int confirm_yes_no(const char* prompt);

/* Muestra address de 20 bytes para verificación visual. Espera A. */
void confirm_show_address(const u8 address[20]);

/* Resultado de la tx tras intentar broadcast en el host.
 *
 *   status = 0x00 : broadcast OK   -> hash[32] valido, errmsg ignorado
 *   status = 0x01 : broadcast ERR  -> errmsg/errlen valido, hash ignorado
 *   status = 0x02 : NO BROADCAST   -> firma OK pero host no envio (modo audit)
 *
 * Espera A para volver. */
void confirm_show_tx_result(u8 status,
                            const u8 hash[32],
                            const char* errmsg, u32 errlen);

/* Pantalla "BROADCASTING..." con spinner cooperativo, mostrada mientras
 * esperamos PROTO_TXRESULT del host. Solo dibuja el frame inicial; quien
 * la llama hace su propio loop animando el spinner. */
void confirm_show_broadcasting(void);

#endif
