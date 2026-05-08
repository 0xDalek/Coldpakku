#include "hmac_sha512.h"

#include <string.h>

#define BLOCK 128

void hmac_sha512_init(hmac_sha512_ctx* ctx, const u8* key, u32 keylen) {
    u8 kbuf[BLOCK];
    if (keylen > BLOCK) {
        sha512(key, keylen, kbuf);
        memset(kbuf + 64, 0, BLOCK - 64);
    } else {
        memcpy(kbuf, key, keylen);
        memset(kbuf + keylen, 0, BLOCK - keylen);
    }
    u8 ipad[BLOCK], opad[BLOCK];
    for (int i = 0; i < BLOCK; i++) {
        ipad[i] = kbuf[i] ^ 0x36;
        opad[i] = kbuf[i] ^ 0x5c;
    }
    sha512_init(&ctx->inner);
    sha512_update(&ctx->inner, ipad, BLOCK);
    sha512_init(&ctx->outer);
    sha512_update(&ctx->outer, opad, BLOCK);
    /* zeroizar buffers locales */
    memset(kbuf, 0, BLOCK);
    memset(ipad, 0, BLOCK);
    memset(opad, 0, BLOCK);
}

void hmac_sha512_update(hmac_sha512_ctx* ctx, const u8* data, u32 len) {
    sha512_update(&ctx->inner, data, len);
}

void hmac_sha512_final(hmac_sha512_ctx* ctx, u8 out[64]) {
    u8 inner_hash[64];
    sha512_final(&ctx->inner, inner_hash);
    sha512_update(&ctx->outer, inner_hash, 64);
    sha512_final(&ctx->outer, out);
    memset(inner_hash, 0, 64);
}

void hmac_sha512(const u8* key, u32 keylen,
                 const u8* msg, u32 msglen,
                 u8 out[64]) {
    hmac_sha512_ctx ctx;
    hmac_sha512_init(&ctx, key, keylen);
    hmac_sha512_update(&ctx, msg, msglen);
    hmac_sha512_final(&ctx, out);
}
