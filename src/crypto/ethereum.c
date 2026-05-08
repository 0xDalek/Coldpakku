/*
 * Capa Ethereum: address derivation y firma RFC 6979.
 *
 * Sobre el campo v:
 *   micro-ecc no expone una función pública de point recovery, por lo que
 *   on-device no podemos calcular recid sin reimplementar la aritmética de
 *   curva. Solución pragmática: escribimos v = 0xFE como sentinel y dejamos
 *   que el host (Python con eth_account) pruebe recid=0 y recid=1 hasta
 *   encontrar el que recupera la address conocida. Es 1 ms extra del lado PC
 *   y nos ahorra ~2 KB de código en la ROM.
 *
 *   Una vez tengamos un recover propio, sustituiremos esto por v = 27 + recid.
 *
 * Sobre low-s (EIP-2):
 *   uECC_sign_deterministic puede producir firmas con s en la mitad alta del
 *   orden de la curva (s > N/2). Geth, Erigon y demas nodos rechazan esas
 *   firmas como `ECDSA: bad signature`. Antes lo arreglabamos en el host con
 *   normalize_low_s; ahora lo hacemos aqui mismo para que la firma cruda que
 *   sale del GBA sea ya canonical y compatible con cualquier wallet sin
 *   tweaks externos.
 *
 *   Cuando flipeamos s -> N - s tambien se flipea el bit `y_parity` del
 *   recid. Como aqui no calculamos recid (sentinel 0xFE), no hace falta
 *   tocarlo: el host hara su brute force con recid in {0,1} sobre la firma
 *   ya canonical y dara con el correcto.
 */
#include "ethereum.h"
#include "keccak256.h"
#include "sha256.h"
#include "uECC.h"

#include <string.h>

/* Orden del subgrupo secp256k1 (N) y su mitad (N/2 redondeado hacia abajo).
 * Big-endian, 32 bytes cada uno. Constantes de RFC 5639 / SEC 2. */
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

/* Comparacion big-endian unsigned. Devuelve <0, 0, >0 al estilo memcmp. */
static int cmp_be32(const u8 a[32], const u8 b[32]) {
    return memcmp(a, b, 32);
}

/* out = a - b (mod 2^256). Asume a >= b para que no haya borrow final
 * negativo. Big-endian. */
static void sub_be32(u8 out[32], const u8 a[32], const u8 b[32]) {
    int borrow = 0;
    for (int i = 31; i >= 0; i--) {
        int diff = (int)a[i] - (int)b[i] - borrow;
        if (diff < 0) { diff += 256; borrow = 1; }
        else            borrow = 0;
        out[i] = (u8)diff;
    }
}

/* Si s > N/2, sustituye s por N - s in-place. EIP-2 (Homestead). */
static void normalize_low_s(u8 s[32]) {
    if (cmp_be32(s, SECP256K1_HALF_N) > 0) {
        u8 ns[32];
        sub_be32(ns, SECP256K1_N, s);
        memcpy(s, ns, 32);
    }
}

/* Hash context para uECC_sign_deterministic, usando SHA-256 (B-Con). */
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
    u8 tmp[2 * 32 + 64];   /* result_size*2 + block_size segun docs micro-ecc */
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
    /* Canonicaliza s a la mitad baja del orden N (EIP-2). Sin esto los
     * nodos rechazan la firma con `transaction signature is invalid` y el
     * usuario lo ve como "RPC error" en la nueva pantalla TX RESULT. */
    normalize_low_s(sig + 32);
    sig[64] = 0xFE;   /* sentinel: el PC calcula v real probando recid 0/1 */
    memset(tmp, 0, sizeof(tmp));
    return 1;
}

int eth_verify_recover(const u8 hash[32], const u8 sig[65], const u8 expected_addr[20]) {
    /* Verificación on-device opcional vía uECC_verify reusing pubkey local.
     * Sin pubkey local no podemos verificar la firma; esta función la
     * dejamos como stub para uso futuro (e.g. comparar tras descifrar SRAM). */
    (void)hash; (void)sig; (void)expected_addr;
    return 0;
}

/* EIP-55: cada nibble hex del address se pasa a mayúscula si el nibble
 * correspondiente del keccak256 del hex en minúsculas es >= 8. */
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
