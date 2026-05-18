/*
 * SHA-512 (FIPS 180-4) — compact implementation for ARM7TDMI.
 * No libc dependencies besides memcpy. Uses 64-bit emulation via
 * __aeabi_* helpers provided by gcc.
 */
#include "sha512.h"

#include <string.h>

static const u64 K[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

static const u64 H0[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

#define ROTR(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#define CH(x,y,z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define BSIG0(x)   (ROTR(x,28) ^ ROTR(x,34) ^ ROTR(x,39))
#define BSIG1(x)   (ROTR(x,14) ^ ROTR(x,18) ^ ROTR(x,41))
#define SSIG0(x)   (ROTR(x,1)  ^ ROTR(x,8)  ^ ((x) >> 7))
#define SSIG1(x)   (ROTR(x,19) ^ ROTR(x,61) ^ ((x) >> 6))

static u64 load_be64(const u8* p) {
    return ((u64)p[0] << 56) | ((u64)p[1] << 48) | ((u64)p[2] << 40) | ((u64)p[3] << 32)
         | ((u64)p[4] << 24) | ((u64)p[5] << 16) | ((u64)p[6] <<  8) | ((u64)p[7]);
}

static void store_be64(u8* p, u64 v) {
    p[0] = (u8)(v >> 56); p[1] = (u8)(v >> 48); p[2] = (u8)(v >> 40); p[3] = (u8)(v >> 32);
    p[4] = (u8)(v >> 24); p[5] = (u8)(v >> 16); p[6] = (u8)(v >>  8); p[7] = (u8)(v);
}

static void compress(sha512_ctx* ctx, const u8 block[128]) {
    u64 W[80];
    for (int i = 0; i < 16; i++) W[i] = load_be64(block + i * 8);
    for (int i = 16; i < 80; i++) {
        W[i] = SSIG1(W[i-2]) + W[i-7] + SSIG0(W[i-15]) + W[i-16];
    }
    u64 a = ctx->state[0], b = ctx->state[1], c = ctx->state[2], d = ctx->state[3];
    u64 e = ctx->state[4], f = ctx->state[5], g = ctx->state[6], h = ctx->state[7];
    for (int i = 0; i < 80; i++) {
        u64 t1 = h + BSIG1(e) + CH(e,f,g) + K[i] + W[i];
        u64 t2 = BSIG0(a) + MAJ(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

void sha512_init(sha512_ctx* ctx) {
    memcpy(ctx->state, H0, sizeof(H0));
    ctx->bitlen_hi = 0;
    ctx->bitlen_lo = 0;
    ctx->buflen = 0;
}

static void add_bits(sha512_ctx* ctx, u64 bits) {
    u64 old = ctx->bitlen_lo;
    ctx->bitlen_lo += bits;
    if (ctx->bitlen_lo < old) ctx->bitlen_hi++;
}

void sha512_update(sha512_ctx* ctx, const u8* data, u32 len) {
    add_bits(ctx, (u64)len * 8);
    if (ctx->buflen) {
        u32 need = SHA512_BLOCK_SIZE - ctx->buflen;
        if (len < need) {
            memcpy(ctx->buf + ctx->buflen, data, len);
            ctx->buflen += len;
            return;
        }
        memcpy(ctx->buf + ctx->buflen, data, need);
        compress(ctx, ctx->buf);
        data += need; len -= need; ctx->buflen = 0;
    }
    while (len >= SHA512_BLOCK_SIZE) {
        compress(ctx, data);
        data += SHA512_BLOCK_SIZE;
        len  -= SHA512_BLOCK_SIZE;
    }
    if (len) { memcpy(ctx->buf, data, len); ctx->buflen = len; }
}

void sha512_final(sha512_ctx* ctx, u8 out[SHA512_DIGEST_SIZE]) {
    u64 bl_hi = ctx->bitlen_hi, bl_lo = ctx->bitlen_lo;
    ctx->buf[ctx->buflen++] = 0x80;
    if (ctx->buflen > 112) {
        memset(ctx->buf + ctx->buflen, 0, SHA512_BLOCK_SIZE - ctx->buflen);
        compress(ctx, ctx->buf);
        ctx->buflen = 0;
    }
    memset(ctx->buf + ctx->buflen, 0, 112 - ctx->buflen);
    store_be64(ctx->buf + 112, bl_hi);
    store_be64(ctx->buf + 120, bl_lo);
    compress(ctx, ctx->buf);
    for (int i = 0; i < 8; i++) store_be64(out + i * 8, ctx->state[i]);
}

void sha512(const u8* data, u32 len, u8 out[SHA512_DIGEST_SIZE]) {
    sha512_ctx ctx;
    sha512_init(&ctx);
    sha512_update(&ctx, data, len);
    sha512_final(&ctx, out);
}
