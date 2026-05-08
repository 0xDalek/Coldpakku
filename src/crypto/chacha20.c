#include "crypto.h"
#include <string.h>

#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32u - (n))))

#define QR(a, b, c, d) do { \
    (a) += (b); (d) ^= (a); (d) = ROTL32((d), 16u); \
    (c) += (d); (b) ^= (c); (b) = ROTL32((b), 12u); \
    (a) += (b); (d) ^= (a); (d) = ROTL32((d),  8u); \
    (c) += (d); (b) ^= (c); (b) = ROTL32((b),  7u); \
} while (0)

/* One 64-byte ChaCha20 keystream block (20 rounds). */
static void chacha20_block(const u32 key[8], const u32 nonce[3],
                           u32 counter, u8 out[64]) {
    u32 x[16];
    u32 init[16];
    u32 i;

    /* "expand 32-byte k" constants */
    x[0]  = 0x61707865u;
    x[1]  = 0x3320646eu;
    x[2]  = 0x79622d32u;
    x[3]  = 0x6b206574u;

    x[4]  = key[0];  x[5]  = key[1];  x[6]  = key[2];  x[7]  = key[3];
    x[8]  = key[4];  x[9]  = key[5];  x[10] = key[6];  x[11] = key[7];

    x[12] = counter;
    x[13] = nonce[0];
    x[14] = nonce[1];
    x[15] = nonce[2];

    for (i = 0u; i < 16u; i++) { init[i] = x[i]; }

    /* 10 double-rounds = 20 rounds */
    for (i = 0u; i < 10u; i++) {
        QR(x[0], x[4], x[8],  x[12]);
        QR(x[1], x[5], x[9],  x[13]);
        QR(x[2], x[6], x[10], x[14]);
        QR(x[3], x[7], x[11], x[15]);
        QR(x[0], x[5], x[10], x[15]);
        QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[8],  x[13]);
        QR(x[3], x[4], x[9],  x[14]);
    }

    /* Add initial state and serialize little-endian */
    for (i = 0u; i < 16u; i++) {
        u32 v = x[i] + init[i];
        out[i * 4u + 0u] = (u8)(v);
        out[i * 4u + 1u] = (u8)(v >>  8u);
        out[i * 4u + 2u] = (u8)(v >> 16u);
        out[i * 4u + 3u] = (u8)(v >> 24u);
    }
}

void chacha20_xor(const u8 key[32], const u8 nonce[12], u32 counter,
                  const u8* in, u8* out, u32 len) {
    u32 key32[8];
    u32 nonce32[3];
    u8  block[64];
    u32 pos = 0u;
    u32 i;

    /* Pack key and nonce as little-endian u32 words */
    for (i = 0u; i < 8u; i++) {
        key32[i] = (u32)key[i * 4u]
                 | ((u32)key[i * 4u + 1u] <<  8u)
                 | ((u32)key[i * 4u + 2u] << 16u)
                 | ((u32)key[i * 4u + 3u] << 24u);
    }
    for (i = 0u; i < 3u; i++) {
        nonce32[i] = (u32)nonce[i * 4u]
                   | ((u32)nonce[i * 4u + 1u] <<  8u)
                   | ((u32)nonce[i * 4u + 2u] << 16u)
                   | ((u32)nonce[i * 4u + 3u] << 24u);
    }

    while (pos < len) {
        u32 chunk = len - pos;
        if (chunk > 64u) { chunk = 64u; }
        chacha20_block(key32, nonce32, counter, block);
        counter++;
        for (i = 0u; i < chunk; i++) {
            out[pos + i] = in[pos + i] ^ block[i];
        }
        pos += chunk;
    }

    memset(block, 0, sizeof(block));
}

void crypto_fill_random(u8* buf, u32 len) {
    /* GBA hardware timer count registers */
    volatile u16* TM0 = (volatile u16*)0x04000100u;
    volatile u16* TM1 = (volatile u16*)0x04000104u;
    volatile u16* TM2 = (volatile u16*)0x04000108u;
    volatile u16* TM3 = (volatile u16*)0x0400010Cu;
    static u32 s_ctr = 0u;
    u32 i;

    for (i = 0u; i < len; i++) {
        u32 mix;
        s_ctr++;
        /* Mix timer samples + internal counter */
        mix = (u32)(*TM0)
            ^ ((u32)(*TM1) <<  5u)
            ^ ((u32)(*TM2) << 11u)
            ^ ((u32)(*TM3) << 19u)
            ^ (s_ctr * 2654435769u); /* Knuth multiplicative constant */
        /* Fold to one byte */
        mix ^= (mix >> 16u);
        mix ^= (mix >>  8u);
        buf[i] = (u8)mix;
        /* Tiny delay so timers advance between samples */
        { volatile u32 d; for (d = 0u; d < 16u; d++) {} }
    }
}
