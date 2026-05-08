#ifndef CRYPTO_H
#define CRYPTO_H

#include <gba_types.h>

/*
 * ChaCha20 for GBA bare metal (RFC 8439).
 * No heap, no external deps, no libc crypto.
 */

/*
 * XOR 'len' bytes with ChaCha20 keystream (encrypt/decrypt).
 *   key     : 32 bytes
 *   nonce   : 12 bytes (96-bit, RFC 8439)
 *   counter : initial block counter (0 or 1)
 *   in/out  : may alias (in-place OK).
 */
void chacha20_xor(const u8 key[32], const u8 nonce[12], u32 counter,
                  const u8* in, u8* out, u32 len);

/*
 * Fill 'len' bytes with pseudo-random data derived from GBA hardware timers.
 * Not a CSPRNG, but produces non-repeating output between calls for nonces.
 */
void crypto_fill_random(u8* buf, u32 len);

#endif /* CRYPTO_H */
