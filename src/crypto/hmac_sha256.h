#ifndef HMAC_SHA256_H
#define HMAC_SHA256_H

#include <gba_types.h>

/* HMAC-SHA-256 (RFC 2104). Salida = 32 bytes. */
void hmac_sha256(const u8* key, u32 keylen,
                 const u8* msg, u32 msglen,
                 u8 out[32]);

#endif
