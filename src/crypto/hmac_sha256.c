#include "hmac_sha256.h"
#include "sha256.h"

#include <string.h>

#define HMAC_SHA256_BLOCK 64
#define HMAC_SHA256_OUT   32

void hmac_sha256(const u8* key, u32 keylen,
                 const u8* msg, u32 msglen,
                 u8 out[32]) {
    u8 k[HMAC_SHA256_BLOCK];
    SHA256_CTX s;

    /* 1. Normalise the key to block size */
    if (keylen > HMAC_SHA256_BLOCK) {
        sha256_init(&s);
        sha256_update(&s, (const BYTE*)key, keylen);
        sha256_final(&s, k);
        memset(k + HMAC_SHA256_OUT, 0, HMAC_SHA256_BLOCK - HMAC_SHA256_OUT);
    } else {
        memcpy(k, key, keylen);
        if (keylen < HMAC_SHA256_BLOCK) {
            memset(k + keylen, 0, HMAC_SHA256_BLOCK - keylen);
        }
    }

    /* 2. inner = SHA256( (k XOR 0x36) || msg ) */
    u8 ipad[HMAC_SHA256_BLOCK];
    for (int i = 0; i < HMAC_SHA256_BLOCK; i++) ipad[i] = k[i] ^ 0x36;
    u8 inner[HMAC_SHA256_OUT];
    sha256_init(&s);
    sha256_update(&s, ipad, HMAC_SHA256_BLOCK);
    sha256_update(&s, (const BYTE*)msg, msglen);
    sha256_final(&s, inner);

    /* 3. out = SHA256( (k XOR 0x5C) || inner ) */
    u8 opad[HMAC_SHA256_BLOCK];
    for (int i = 0; i < HMAC_SHA256_BLOCK; i++) opad[i] = k[i] ^ 0x5C;
    sha256_init(&s);
    sha256_update(&s, opad, HMAC_SHA256_BLOCK);
    sha256_update(&s, inner, HMAC_SHA256_OUT);
    sha256_final(&s, out);

    /* zeroise temporary material */
    memset(k, 0, sizeof(k));
    memset(ipad, 0, sizeof(ipad));
    memset(opad, 0, sizeof(opad));
    memset(inner, 0, sizeof(inner));
    memset(&s, 0, sizeof(s));
}
