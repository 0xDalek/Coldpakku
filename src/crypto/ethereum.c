/*
 * Ethereum layer: address derivation and RFC 6979 signing.
 *
 * On the `v` field:
 *   micro-ecc does not expose a public point-recovery function, so
 *   on-device we cannot compute recid without re-implementing curve
 *   arithmetic. Pragmatic solution: we write v = 0xFE as a sentinel and
 *   let the host (Python with eth_account) try recid=0 and recid=1
 *   until it finds the one that recovers the known address. It's 1 ms
 *   extra on the PC side and saves us ~2 KB of code in the ROM.
 *
 *   Once we have a native recover, we will replace this with
 *   v = 27 + recid.
 *
 * On low-s (EIP-2):
 *   uECC_sign_deterministic can produce signatures with s in the upper
 *   half of the curve order (s > N/2). Geth, Erigon, and other nodes
 *   reject those signatures with `ECDSA: bad signature`. We used to fix
 *   this on the host with normalize_low_s; now we do it here so the
 *   raw signature coming out of the GBA is already canonical and
 *   compatible with any wallet without external tweaks.
 *
 *   When we flip s -> N - s the recid `y_parity` bit also flips. Since
 *   we don't compute recid here (sentinel 0xFE), we don't need to do
 *   anything: the host brute-forces recid in {0,1} over the already
 *   canonical signature and finds the right one.
 */
#include "ethereum.h"
#include "keccak256.h"
#include "sha256.h"
#include "uECC.h"

#include <string.h>

/* secp256k1 subgroup order (N) and its half (N/2 rounded down).
 * Big-endian, 32 bytes each. Constants from RFC 5639 / SEC 2. */
static const u8 SECP256K1_N[32] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
    0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,
    0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41
};
static const u8 SECP256K1_HALF_N[32] = {
    0x7F,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0x5D,0x57,0x6E,0x73,0x57,0xA4,0x50,0x1D,
    0xDF,0xE9,0x2F,0x46,0x68,0x1B,0x20,0xA0
};

/* Unsigned big-endian comparison. Returns <0, 0, >0 like memcmp. */
static int cmp_be32(const u8 a[32], const u8 b[32]) {
    return memcmp(a, b, 32);
}

/* out = a - b (mod 2^256). Assumes a >= b so there's no final negative
 * borrow. Big-endian. */
static void sub_be32(u8 out[32], const u8 a[32], const u8 b[32]) {
    int borrow = 0;
    for (int i = 31; i >= 0; i--) {
        int diff = (int)a[i] - (int)b[i] - borrow;
        if (diff < 0) { diff += 256; borrow = 1; }
        else            borrow = 0;
        out[i] = (u8)diff;
    }
}

/* If s > N/2, replace s with N - s in-place. EIP-2 (Homestead). */
static void normalize_low_s(u8 s[32]) {
    if (cmp_be32(s, SECP256K1_HALF_N) > 0) {
        u8 ns[32];
        sub_be32(ns, SECP256K1_N, s);
        memcpy(s, ns, 32);
    }
}

/* Hash context for uECC_sign_deterministic, using SHA-256 (B-Con). */
typedef struct {
    uECC_HashContext base;
    SHA256_CTX ctx;
} sha256_hash_ctx;

static void s256_init(const uECC_HashContext* base) {
    sha256_init(&((sha256_hash_ctx*)base)->ctx);
}
static void s256_update(const uECC_HashContext* base, const uint8_t* msg, unsigned len) {
    sha256_update(&((sha256_hash_ctx*)base)->ctx, msg, len);
}
static void s256_finish(const uECC_HashContext* base, uint8_t* out) {
    sha256_final(&((sha256_hash_ctx*)base)->ctx, out);
}

int eth_priv_to_address(const u8 priv[32], u8 address[20], u8 out_pubkey[64]) {
    u8 pub64[64];
    if (!uECC_compute_public_key(priv, pub64, uECC_secp256k1())) return 0;
    if (out_pubkey) memcpy(out_pubkey, pub64, 64);
    u8 hash[32];
    keccak256(pub64, 64, hash);
    memcpy(address, hash + 12, 20);
    return 1;
}

int eth_sign_hash(const u8 priv[32], const u8 hash[32], u8 sig[65]) {
    u8 tmp[2 * 32 + 64];   /* result_size*2 + block_size per micro-ecc docs */
    sha256_hash_ctx hc;
    hc.base.init_hash    = s256_init;
    hc.base.update_hash  = s256_update;
    hc.base.finish_hash  = s256_finish;
    hc.base.block_size   = 64;
    hc.base.result_size  = 32;
    hc.base.tmp          = tmp;
    if (!uECC_sign_deterministic(priv, hash, 32, &hc.base, sig, uECC_secp256k1())) {
        memset(tmp, 0, sizeof(tmp));
        return 0;
    }
    /* Canonicalise s to the lower half of order N (EIP-2). Without this
     * the nodes reject the signature with `transaction signature is
     * invalid` and the user sees it as an "RPC error" on the TX RESULT
     * screen. */
    normalize_low_s(sig + 32);
    sig[64] = 0xFE;   /* sentinel: the PC computes the real v by trying recid 0/1 */
    memset(tmp, 0, sizeof(tmp));
    return 1;
}

int eth_verify_recover(const u8 hash[32], const u8 sig[65], const u8 expected_addr[20]) {
    /* Optional on-device verification via uECC_verify reusing the local
     * pubkey. Without a local pubkey we cannot verify the signature;
     * we leave this function as a stub for future use (e.g. compare
     * after decrypting SRAM). */
    (void)hash; (void)sig; (void)expected_addr;
    return 0;
}

/* EIP-55: each hex nibble of the address is uppercased if the
 * corresponding nibble of keccak256 over the lowercase hex is >= 8. */
void eth_address_to_eip55(const u8 address[20], char out[43]) {
    static const char* lower = "0123456789abcdef";
    char hex_lower[40];
    for (int i = 0; i < 20; i++) {
        hex_lower[i * 2]     = lower[(address[i] >> 4) & 0x0F];
        hex_lower[i * 2 + 1] = lower[address[i] & 0x0F];
    }
    u8 h[32];
    keccak256((const u8*)hex_lower, 40, h);
    out[0] = '0'; out[1] = 'x';
    for (int i = 0; i < 40; i++) {
        char c = hex_lower[i];
        u8 nibble = (i & 1) ? (h[i / 2] & 0x0F) : (h[i / 2] >> 4);
        if (c >= 'a' && c <= 'f' && nibble >= 8) c -= 32; /* a -> A */
        out[2 + i] = c;
    }
    out[42] = 0;
}
