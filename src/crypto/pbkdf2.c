/*
 * PBKDF2-HMAC-SHA512 con un único bloque (dklen=64).
 *
 * Optimización: cuando computamos U_2..U_c lo que cambia respecto al U_1
 * es solo el mensaje. Pero como en cada iteración el mensaje es 64 bytes,
 * podemos pre-cachar los estados ipad/opad del HMAC y reusarlos: cada
 * iteración cuesta 2 compresiones SHA-512 (1 inner + 1 outer) en lugar
 * de 4 si se reinicializase HMAC desde la clave.
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
    hmac_sha512_ctx h1 = base;  /* copia estructural; init() ya hizo los ipad/opad */
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
