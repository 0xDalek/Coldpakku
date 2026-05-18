/*
 * PBKDF2-HMAC-SHA512 with a single block (dklen=64).
 *
 * Optimisation: when we compute U_2..U_c what changes compared to U_1
 * is only the message. But since each iteration's message is 64 bytes,
 * we can pre-cache the HMAC ipad/opad states and reuse them: each
 * iteration costs 2 SHA-512 compressions (1 inner + 1 outer) instead
 * of 4 if HMAC were reinitialised from the key.
 */
#include "pbkdf2.h"
#include "sha512.h"
#include "hmac_sha512.h"

#include <string.h>

#define HLEN 64
#define BLOCK 128

void pbkdf2_hmac_sha512_64(const u8* password, u32 plen,
                           const u8* salt,     u32 slen,
                           u32 iterations,
                           u8  out[HLEN],
                           pbkdf2_progress_fn progress, void* ud) {
    /* T_1 = U_1 XOR U_2 XOR ... XOR U_c
       U_1 = HMAC(password, salt || INT(1))
       U_i = HMAC(password, U_{i-1}) */

    hmac_sha512_ctx base;
    hmac_sha512_init(&base, password, plen);

    /* U_1 */
    hmac_sha512_ctx h1 = base;  /* structural copy; init() already prepared ipad/opad */
    u8 idx_be[4] = {0, 0, 0, 1};
    hmac_sha512_update(&h1, salt, slen);
    hmac_sha512_update(&h1, idx_be, 4);
    u8 U[HLEN];
    hmac_sha512_final(&h1, U);
    memcpy(out, U, HLEN);

    if (progress) progress(1, iterations, ud);

    for (u32 i = 2; i <= iterations; i++) {
        hmac_sha512_ctx hi = base;
        hmac_sha512_update(&hi, U, HLEN);
        hmac_sha512_final(&hi, U);
        for (u32 j = 0; j < HLEN; j++) out[j] ^= U[j];
        if (progress && (i & 0x3F) == 0) progress(i, iterations, ud);
    }
    if (progress) progress(iterations, iterations, ud);

    memset(U, 0, HLEN);
    memset(&base, 0, sizeof(base));
}
