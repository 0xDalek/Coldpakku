/*
 * BIP32 derivación HD para secp256k1.
 *
 * Hardened (i >= 2^31): I = HMAC-SHA512(chain, 0x00 || ser256(priv) || ser32(i))
 * Non-hardened:         I = HMAC-SHA512(chain, ser_p(K_par) || ser32(i))
 *   donde ser_p(K_par) es el pubkey comprimido (33 bytes, prefijo 02/03).
 *
 * priv_child = (IL + priv_parent) mod n
 * chain_child = IR
 *
 * Necesitamos suma modular en n del orden de secp256k1. micro-ecc no
 * expone esa primitiva públicamente, así que la implementamos con BIGINT
 * 256-bit propio (suma + resta condicional).
 */
#include "bip32.h"
#include "hmac_sha512.h"

#include "uECC.h"

#include <string.h>

/* n de secp256k1 (orden del grupo) en big-endian */
static const u8 SECP256K1_N[32] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
    0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,
    0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41
};

/* a >= b ? */
static int be_ge(const u8 a[32], const u8 b[32]) {
    for (int i = 0; i < 32; i++) {
        if (a[i] != b[i]) return a[i] > b[i];
    }
    return 1;
}

static int be_is_zero(const u8 a[32]) {
    for (int i = 0; i < 32; i++) if (a[i]) return 0;
    return 1;
}

/* a += b (mod 2^256). Devuelve carry. */
static u32 be_add(u8 a[32], const u8 b[32]) {
    u32 c = 0;
    for (int i = 31; i >= 0; i--) {
        u32 s = (u32)a[i] + (u32)b[i] + c;
        a[i] = (u8)(s & 0xFF);
        c = s >> 8;
    }
    return c;
}

/* a -= b. Devuelve borrow. */
static u32 be_sub(u8 a[32], const u8 b[32]) {
    u32 br = 0;
    for (int i = 31; i >= 0; i--) {
        s32 d = (s32)a[i] - (s32)b[i] - (s32)br;
        if (d < 0) { d += 256; br = 1; } else br = 0;
        a[i] = (u8)d;
    }
    return br;
}

/* (a + b) mod n */
static void be_add_mod_n(u8 a[32], const u8 b[32]) {
    u32 c = be_add(a, b);
    /* si hay carry o el resultado >= n, restar n */
    if (c || be_ge(a, SECP256K1_N)) {
        be_sub(a, SECP256K1_N);
    }
}

void bip32_master(const u8 seed[64], bip32_node* out) {
    static const u8 key[12] = {'B','i','t','c','o','i','n',' ','s','e','e','d'};
    u8 I[64];
    hmac_sha512(key, 12, seed, 64, I);
    memcpy(out->priv,  I,      32);
    memcpy(out->chain, I + 32, 32);
    memset(I, 0, 64);
}

int bip32_ckd(const bip32_node* in, u32 index, bip32_node* out) {
    u8 data[37];
    u8 I[64];

    if (index >= BIP32_HARDENED) {
        data[0] = 0x00;
        memcpy(data + 1, in->priv, 32);
    } else {
        u8 pub64[64];
        if (!uECC_compute_public_key(in->priv, pub64, uECC_secp256k1())) return 0;
        /* compress: 0x02 si y par, 0x03 si y impar; x = pub64[0..32] */
        data[0] = (pub64[63] & 1) ? 0x03 : 0x02;
        memcpy(data + 1, pub64, 32);
    }
    data[33] = (u8)(index >> 24);
    data[34] = (u8)(index >> 16);
    data[35] = (u8)(index >> 8);
    data[36] = (u8)(index);

    hmac_sha512(in->chain, 32, data, 37, I);

    /* Validar: IL < n y child priv != 0; si no, retry con next index (raro, ignoramos por simplicidad). */
    if (!be_ge(SECP256K1_N, I) || be_is_zero(I)) {
        memset(I, 0, 64);
        return 0;
    }
    /* IL >= n? */
    if (be_ge(I, SECP256K1_N)) {
        memset(I, 0, 64);
        return 0;
    }

    u8 child_priv[32];
    memcpy(child_priv, I, 32);
    be_add_mod_n(child_priv, in->priv);
    if (be_is_zero(child_priv)) {
        memset(I, 0, 64);
        memset(child_priv, 0, 32);
        return 0;
    }
    memcpy(out->priv, child_priv, 32);
    memcpy(out->chain, I + 32, 32);
    memset(I, 0, 64);
    memset(child_priv, 0, 32);
    return 1;
}

int bip32_derive_eth_default(const bip32_node* master, bip32_node* out) {
    /* m / 44' / 60' / 0' / 0 / 0 */
    bip32_node a, b;
    if (!bip32_ckd(master, BIP32_HARDENED + 44, &a)) return 0;
    if (!bip32_ckd(&a, BIP32_HARDENED + 60, &b)) return 0;
    if (!bip32_ckd(&b, BIP32_HARDENED + 0,  &a)) return 0;
    if (!bip32_ckd(&a, 0, &b)) return 0;
    if (!bip32_ckd(&b, 0, out)) return 0;
    memset(&a, 0, sizeof(a));
    memset(&b, 0, sizeof(b));
    return 1;
}
