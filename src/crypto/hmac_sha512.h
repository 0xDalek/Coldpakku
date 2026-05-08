#ifndef HMAC_SHA512_H
#define HMAC_SHA512_H

#include <gba_types.h>
#include "sha512.h"

typedef struct {
    sha512_ctx inner;
    sha512_ctx outer;
} hmac_sha512_ctx;

void hmac_sha512_init(hmac_sha512_ctx* ctx, const u8* key, u32 keylen);
void hmac_sha512_update(hmac_sha512_ctx* ctx, const u8* data, u32 len);
void hmac_sha512_final(hmac_sha512_ctx* ctx, u8 out[64]);

void hmac_sha512(const u8* key, u32 keylen,
                 const u8* msg, u32 msglen,
                 u8 out[64]);

#endif
