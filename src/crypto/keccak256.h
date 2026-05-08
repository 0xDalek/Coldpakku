#ifndef KECCAK256_H
#define KECCAK256_H

#include "../types.h"

/* Keccak-256 (NO SHA3-256). La diferencia es el byte de padding (0x01 vs 0x06).
 * Es la función hash usada por Ethereum.
 *
 *   keccak256(in, len) -> 32 bytes
 */

void keccak256(const u8* in, u32 len, u8 out[32]);

typedef struct {
    u64 state[25];
    u32 buflen;
    u8  buf[136];   /* rate = 1088 bits = 136 bytes */
} keccak256_ctx;

void keccak256_init(keccak256_ctx* ctx);
void keccak256_update(keccak256_ctx* ctx, const u8* data, u32 len);
void keccak256_final(keccak256_ctx* ctx, u8 out[32]);

#endif
