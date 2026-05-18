/*
 * Keccak-256 — compact implementation (based on the FIPS-202 description).
 * 0x01 padding (not 0x06 like SHA3-256). Output = 32 bytes. Rate = 136 bytes.
 *
 * Permutation: 24 rounds (Theta, Rho, Pi, Chi, Iota).
 * State: 25 lanes of 64 bits.
 */
#include "keccak256.h"

#include <string.h>

#define ROL64(x, n) (((x) << (n)) | ((x) >> (64 - (n))))

static const u64 RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

static const u8 R[24] = {
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
    27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
};

static const u8 PI[24] = {
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
};

static void keccakf(u64 s[25]) {
    u64 BC[5], t;
    for (int round = 0; round < 24; round++) {
        /* Theta */
        for (int i = 0; i < 5; i++)
            BC[i] = s[i] ^ s[i+5] ^ s[i+10] ^ s[i+15] ^ s[i+20];
        for (int i = 0; i < 5; i++) {
            t = BC[(i + 4) % 5] ^ ROL64(BC[(i + 1) % 5], 1);
            for (int j = 0; j < 25; j += 5) s[j + i] ^= t;
        }
        /* Rho + Pi */
        t = s[1];
        for (int i = 0; i < 24; i++) {
            int j = PI[i];
            BC[0] = s[j];
            s[j] = ROL64(t, R[i]);
            t = BC[0];
        }
        /* Chi */
        for (int j = 0; j < 25; j += 5) {
            for (int i = 0; i < 5; i++) BC[i] = s[j + i];
            for (int i = 0; i < 5; i++)
                s[j + i] = BC[i] ^ ((~BC[(i + 1) % 5]) & BC[(i + 2) % 5]);
        }
        /* Iota */
        s[0] ^= RC[round];
    }
}

#define RATE 136

void keccak256_init(keccak256_ctx* ctx) {
    memset(ctx, 0, sizeof(*ctx));
}

static void absorb_block(u64 state[25], const u8* block) {
    for (u32 i = 0; i < RATE / 8; i++) {
        u64 v = ((u64)block[i*8 + 0])
              | ((u64)block[i*8 + 1] << 8)
              | ((u64)block[i*8 + 2] << 16)
              | ((u64)block[i*8 + 3] << 24)
              | ((u64)block[i*8 + 4] << 32)
              | ((u64)block[i*8 + 5] << 40)
              | ((u64)block[i*8 + 6] << 48)
              | ((u64)block[i*8 + 7] << 56);
        state[i] ^= v;
    }
    keccakf(state);
}

void keccak256_update(keccak256_ctx* ctx, const u8* data, u32 len) {
    if (ctx->buflen) {
        u32 need = RATE - ctx->buflen;
        if (len < need) {
            memcpy(ctx->buf + ctx->buflen, data, len);
            ctx->buflen += len;
            return;
        }
        memcpy(ctx->buf + ctx->buflen, data, need);
        absorb_block(ctx->state, ctx->buf);
        data += need; len -= need; ctx->buflen = 0;
    }
    while (len >= RATE) {
        absorb_block(ctx->state, data);
        data += RATE; len -= RATE;
    }
    if (len) { memcpy(ctx->buf, data, len); ctx->buflen = len; }
}

void keccak256_final(keccak256_ctx* ctx, u8 out[32]) {
    /* multi-rate padding: append 0x01 at the end of the message and 0x80 at the end of the rate block */
    memset(ctx->buf + ctx->buflen, 0, RATE - ctx->buflen);
    ctx->buf[ctx->buflen] |= 0x01;
    ctx->buf[RATE - 1]   |= 0x80;
    absorb_block(ctx->state, ctx->buf);
    /* squeeze 32 bytes (the first 32 of the state, little-endian per lane) */
    for (u32 i = 0; i < 4; i++) {
        u64 v = ctx->state[i];
        for (u32 j = 0; j < 8; j++) out[i*8 + j] = (u8)(v >> (8 * j));
    }
    memset(ctx, 0, sizeof(*ctx));
}

void keccak256(const u8* in, u32 len, u8 out[32]) {
    keccak256_ctx ctx;
    keccak256_init(&ctx);
    keccak256_update(&ctx, in, len);
    keccak256_final(&ctx, out);
}
