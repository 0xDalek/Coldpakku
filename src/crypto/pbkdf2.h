#ifndef PBKDF2_H
#define PBKDF2_H

#include <gba_types.h>

/*
 * PBKDF2-HMAC-SHA512 (RFC 8018 §5.2). dklen máximo: 64 bytes (un único
 * bloque T_1, suficiente para BIP39 que pide 64 bytes).
 *
 * progress(done, total, ud) opcional: si != NULL, se llama tras cada bloque
 * de iteraciones para refrescar UI.
 */

typedef void (*pbkdf2_progress_fn)(u32 done, u32 total, void* ud);

void pbkdf2_hmac_sha512_64(const u8* password, u32 plen,
                           const u8* salt,     u32 slen,
                           u32 iterations,
                           u8  out[64],
                           pbkdf2_progress_fn progress, void* ud);

#endif
