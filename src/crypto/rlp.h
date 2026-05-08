#ifndef CRYPTO_RLP_H
#define CRYPTO_RLP_H

#include "../types.h"

/*
 * Decoder RLP (Recursive Length Prefix) — Yellow Paper Appendix B.
 *
 * Diseño:
 *   - Zero-copy: rlp_item.data apunta dentro del buffer original, sin
 *     allocación.
 *   - Sin recursión: el iterador desciende explícitamente en listas.
 *   - Tolera entrada arbitraria sin OOB (todos los tamaños se validan
 *     contra el buffer total).
 *
 * Formato (resumido):
 *   byte b0:
 *     0x00..0x7f       string de 1 byte = b0
 *     0x80..0xb7       string de len = b0-0x80 (0..55 bytes)
 *     0xb8..0xbf       string de len = u(b0-0xb7) bytes en BE
 *     0xc0..0xf7       lista con payload = b0-0xc0 (0..55 bytes)
 *     0xf8..0xff       lista con len = u(b0-0xf7) bytes en BE
 */

typedef struct {
    const u8* data;     /* puntero al PAYLOAD (no a la cabecera) */
    u32       len;      /* longitud del payload */
    u8        is_list;  /* 1 si es lista, 0 si es bytes/string */
} rlp_item;

typedef struct {
    const u8* p;
    const u8* end;
} rlp_iter;

/* Decodifica UN item desde buf. Devuelve 1 ok, 0 si malformed.
 * Si consumed != NULL, escribe cuántos bytes ocupó la cabecera+payload. */
int rlp_decode_item(const u8* buf, u32 buflen,
                    rlp_item* out, u32* consumed);

/* Inicializa iterador sobre el payload de una lista. */
void rlp_iter_init(const rlp_item* list, rlp_iter* it);

/* Consume el siguiente item de la lista. 0 = fin o error.
 * Distingue "fin" (ok, no quedan bytes) de "error" (datos corruptos):
 * usa rlp_iter_eof() para chequear. */
int rlp_iter_next(rlp_iter* it, rlp_item* out);
int rlp_iter_eof(const rlp_iter* it);

/* Helpers para convertir un item bytes a entero unsigned.
 * Devuelve 0 si el item no es interpretable como uintN (longitud > N
 * bytes, o leading zeros, que en RLP no están permitidos para enteros). */
int rlp_to_u64(const rlp_item* item, u64* out);

/* Copia un item bytes a out con padding por la izquierda hasta out_len.
 * Útil para campos como `value` (uint256) que se serializan minimal en RLP
 * pero queremos manipular como buffer big-endian de 32 bytes.
 * Devuelve 0 si item->len > out_len. */
int rlp_to_be_padded(const rlp_item* item, u8* out, u32 out_len);

#endif
