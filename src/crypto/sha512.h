#ifndef SHA512_H
#define SHA512_H

#include "../types.h"

#define SHA512_BLOCK_SIZE 128
#define SHA512_DIGEST_SIZE 64

typedef struct {
    u64 state[8];
    u64 bitlen_hi;
    u64 bitlen_lo;
    u8  buf[SHA512_BLOCK_SIZE];
    u32 buflen;
} sha512_ctx;

void sha512_init(sha512_ctx* ctx);
void sha512_update(sha512_ctx* ctx, const u8* data, u32 len);
void sha512_final(sha512_ctx* ctx, u8 out[SHA512_DIGEST_SIZE]);

void sha512(const u8* data, u32 len, u8 out[SHA512_DIGEST_SIZE]);

#endif
