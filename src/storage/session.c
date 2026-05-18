#include "session.h"
#include "sram.h"
#include "../crypto/crypto.h"
#include "../crypto/hmac_sha256.h"
#include "../crypto/pbkdf2.h"
#include "sha256.h"

#include <string.h>

/* ===========================================================================
 * v3 offsets (SESSION_BLOB_SIZE = 133)
 * ===========================================================================
 */
#define V3_OFF_MAGIC    0u
#define V3_OFF_VER      4u
#define V3_OFF_SALT     5u
#define V3_LEN_SALT     16u
#define V3_OFF_NONCE   21u
#define V3_LEN_NONCE    12u
#define V3_OFF_ENCSEED 33u
#define V3_LEN_ENCSEED  64u
#define V3_OFF_MAC     97u
#define V3_LEN_MAC      32u
#define V3_OFF_CRC    129u
#define V3_LEN_CRC      4u
/* Bytes covered by the MAC: version || salt || nonce || enc_seed */
#define V3_MAC_INPUT_OFF  V3_OFF_VER
#define V3_MAC_INPUT_LEN  (1u + V3_LEN_SALT + V3_LEN_NONCE + V3_LEN_ENCSEED)
/* Bytes covered by the CRC: everything except the CRC itself */
#define V3_CRC_INPUT_LEN  V3_OFF_CRC

/* ===========================================================================
 * v2 offsets (legacy, read-only for migration)
 * ===========================================================================
 */
#define V2_OFF_VER      4u
#define V2_OFF_NONCE    5u
#define V2_LEN_NONCE    12u
#define V2_OFF_ENCSEED 17u
#define V2_LEN_ENCSEED  64u
#define V2_OFF_MAC     81u
#define V2_LEN_MAC      32u
#define V2_OFF_CRC    113u
#define V2_MAC_INPUT_OFF V2_OFF_VER
#define V2_MAC_INPUT_LEN (1u + V2_LEN_NONCE + V2_LEN_ENCSEED)
#define V2_CRC_INPUT_LEN V2_OFF_CRC


static u32 crc32(const u8* data, u32 len) {
    u32 crc = 0xFFFFFFFFu;
    for (u32 i = 0; i < len; i++) {
        crc ^= data[i];
        for (int b = 0; b < 8; b++) {
            u32 mask = -(crc & 1u);
            crc = (crc >> 1) ^ (0xEDB88320u & mask);
        }
    }
    return crc ^ 0xFFFFFFFFu;
}

static void put_u32_le(u8 out[4], u32 v) {
    out[0] = (u8)(v);
    out[1] = (u8)(v >> 8);
    out[2] = (u8)(v >> 16);
    out[3] = (u8)(v >> 24);
}
static u32 get_u32_le(const u8 in[4]) {
    return ((u32)in[0]) | ((u32)in[1] << 8)
         | ((u32)in[2] << 16) | ((u32)in[3] << 24);
}

/* Constant-time (no early-exit) comparison for the MAC. */
static int ct_eq_32(const u8 a[32], const u8 b[32]) {
    u32 diff = 0;
    for (int i = 0; i < 32; i++) diff |= (u32)(a[i] ^ b[i]);
    return diff == 0;
}

/* ===========================================================================
 * v3 KDF: PBKDF2-HMAC-SHA512 -> 64 bytes -> split into (key_enc, key_mac).
 * A single PBKDF2 block gives us 64 bytes; we split it in half. Domain
 * separation comes "for free" because the two halves come from different
 * HMAC blocks within PBKDF2 (RFC 8018 fixes INT(1) in the block, and we
 * only request 64 bytes = 1 block here, so we just separate by position).
 * ===========================================================================
 */
static void derive_keys_v3(const char* pin, u32 pin_len,
                           const u8 salt[V3_LEN_SALT],
                           u8 key_enc[32], u8 key_mac[32],
                           pbkdf2_progress_fn progress, void* ud) {
    u8 dk[64];
    pbkdf2_hmac_sha512_64((const u8*)pin, pin_len,
                          salt, V3_LEN_SALT,
                          SESSION_PBKDF2_ITERS_V3,
                          dk, progress, ud);
    memcpy(key_enc, dk,       32);
    memcpy(key_mac, dk + 32,  32);
    memset(dk, 0, sizeof(dk));
}

/* v2 KDF (legacy): SHA256(PIN || 0x01) and SHA256(PIN || 0x02). Only used
 * to load old blobs for migration to v3. Never used on save. */
static void derive_keys_v2(const char* pin, u32 pin_len,
                           u8 key_enc[32], u8 key_mac[32]) {
    SHA256_CTX s;
    u8 sfx;
    sfx = 0x01;
    sha256_init(&s);
    sha256_update(&s, (const BYTE*)pin, pin_len);
    sha256_update(&s, (const BYTE*)&sfx, 1);
    sha256_final(&s, key_enc);
    sfx = 0x02;
    sha256_init(&s);
    sha256_update(&s, (const BYTE*)pin, pin_len);
    sha256_update(&s, (const BYTE*)&sfx, 1);
    sha256_final(&s, key_mac);
    memset(&s, 0, sizeof(s));
}

/* ===========================================================================
 * v3 write: assembles the full blob and writes it to SRAM.
 * ===========================================================================
 */
static void write_v3_blob(const u8 seed[64],
                          const u8 key_enc[32], const u8 key_mac[32],
                          const u8 salt[V3_LEN_SALT],
                          const u8 nonce[V3_LEN_NONCE]) {
    u8 blob[SESSION_BLOB_SIZE];
    memset(blob, 0, sizeof(blob));
    memcpy(blob + V3_OFF_MAGIC, SESSION_MAGIC, 4);
    blob[V3_OFF_VER] = SESSION_VERSION_V3;
    memcpy(blob + V3_OFF_SALT,  salt,  V3_LEN_SALT);
    memcpy(blob + V3_OFF_NONCE, nonce, V3_LEN_NONCE);

    chacha20_xor(key_enc, nonce, 0, seed, blob + V3_OFF_ENCSEED, 64);

    hmac_sha256(key_mac, 32,
                blob + V3_MAC_INPUT_OFF, V3_MAC_INPUT_LEN,
                blob + V3_OFF_MAC);

    u32 crc = crc32(blob, V3_CRC_INPUT_LEN);
    put_u32_le(blob + V3_OFF_CRC, crc);

    sram_write(0, blob, sizeof(blob));
    memset(blob, 0, sizeof(blob));
}

/* ===========================================================================
 * session_present: accepts v2 or v3 with a valid CRC.
 * ===========================================================================
 */
int session_present(void) {
    u8 hdr[5];
    sram_read(0, hdr, sizeof(hdr));
    if (memcmp(hdr, SESSION_MAGIC, 4) != 0) return 0;
    u8 ver = hdr[4];

    if (ver == SESSION_VERSION_V3) {
        u8 blob[SESSION_BLOB_SIZE];
        sram_read(0, blob, sizeof(blob));
        u32 stored = get_u32_le(blob + V3_OFF_CRC);
        u32 actual = crc32(blob, V3_CRC_INPUT_LEN);
        return stored == actual;
    }
    if (ver == SESSION_VERSION_V2) {
        u8 blob[SESSION_BLOB_SIZE_V2];
        sram_read(0, blob, sizeof(blob));
        u32 stored = get_u32_le(blob + V2_OFF_CRC);
        u32 actual = crc32(blob, V2_CRC_INPUT_LEN);
        return stored == actual;
    }
    return 0;
}

/* ===========================================================================
 * session_save (always v3).
 * ===========================================================================
 */
int session_save(const u8 seed[64], const char* pin, u32 pin_len,
                 pbkdf2_progress_fn progress, void* ud) {
    u8 salt[V3_LEN_SALT];
    u8 nonce[V3_LEN_NONCE];
    crypto_fill_random(salt,  V3_LEN_SALT);
    crypto_fill_random(nonce, V3_LEN_NONCE);

    u8 key_enc[32], key_mac[32];
    derive_keys_v3(pin, pin_len, salt, key_enc, key_mac, progress, ud);

    write_v3_blob(seed, key_enc, key_mac, salt, nonce);

    memset(key_enc, 0, sizeof(key_enc));
    memset(key_mac, 0, sizeof(key_mac));
    memset(salt,    0, sizeof(salt));
    memset(nonce,   0, sizeof(nonce));
    return 1;
}

/* ===========================================================================
 * session_load.
 *
 * Reads the header, picks the version and applies the right KDF. If the
 * blob was v2 and the PIN was correct, it is re-encrypted as v3 before
 * returning. The migration pays PBKDF2 only once on this unlock; further
 * unlocks go straight as v3.
 * ===========================================================================
 */
static int load_v3(const u8 blob[SESSION_BLOB_SIZE],
                   const char* pin, u32 pin_len, u8 seed[64],
                   pbkdf2_progress_fn progress, void* ud) {
    u8 key_enc[32], key_mac[32];
    derive_keys_v3(pin, pin_len, blob + V3_OFF_SALT,
                   key_enc, key_mac, progress, ud);

    u8 expected_mac[32];
    hmac_sha256(key_mac, 32,
                blob + V3_MAC_INPUT_OFF, V3_MAC_INPUT_LEN,
                expected_mac);

    int ok = ct_eq_32(blob + V3_OFF_MAC, expected_mac);
    if (ok) {
        chacha20_xor(key_enc, blob + V3_OFF_NONCE, 0,
                     blob + V3_OFF_ENCSEED, seed, 64);
    }

    memset(key_enc,      0, sizeof(key_enc));
    memset(key_mac,      0, sizeof(key_mac));
    memset(expected_mac, 0, sizeof(expected_mac));
    return ok;
}

static int load_v2_and_upgrade(const u8 blob[SESSION_BLOB_SIZE_V2],
                               const char* pin, u32 pin_len, u8 seed[64],
                               pbkdf2_progress_fn progress, void* ud) {
    u8 key_enc[32], key_mac[32];
    derive_keys_v2(pin, pin_len, key_enc, key_mac);

    u8 expected_mac[32];
    hmac_sha256(key_mac, 32,
                blob + V2_MAC_INPUT_OFF, V2_MAC_INPUT_LEN,
                expected_mac);

    int ok = ct_eq_32(blob + V2_OFF_MAC, expected_mac);
    if (ok) {
        chacha20_xor(key_enc, blob + V2_OFF_NONCE, 0,
                     blob + V2_OFF_ENCSEED, seed, 64);
        /* Automatic upgrade to v3: we pay ONE PBKDF2 now. The user is
         * already waiting on the unlock screen, so we reuse the progress
         * callback. After this the blob in SRAM is already v3. */
        session_save(seed, pin, pin_len, progress, ud);
    }

    memset(key_enc,      0, sizeof(key_enc));
    memset(key_mac,      0, sizeof(key_mac));
    memset(expected_mac, 0, sizeof(expected_mac));
    return ok;
}

int session_load(const char* pin, u32 pin_len, u8 seed[64],
                 pbkdf2_progress_fn progress, void* ud) {
    if (!session_present()) return 0;

    u8 ver;
    sram_read(V3_OFF_VER, &ver, 1);   /* same offset as V2_OFF_VER */

    int ok = 0;
    if (ver == SESSION_VERSION_V3) {
        u8 blob[SESSION_BLOB_SIZE];
        sram_read(0, blob, sizeof(blob));
        ok = load_v3(blob, pin, pin_len, seed, progress, ud);
        memset(blob, 0, sizeof(blob));
    } else if (ver == SESSION_VERSION_V2) {
        u8 blob[SESSION_BLOB_SIZE_V2];
        sram_read(0, blob, sizeof(blob));
        ok = load_v2_and_upgrade(blob, pin, pin_len, seed, progress, ud);
        memset(blob, 0, sizeof(blob));
    }

    if (!ok) memset(seed, 0, 64);
    return ok;
}

void session_wipe(void) {
    u8 fill[SESSION_BLOB_SIZE];
    memset(fill, 0xFF, sizeof(fill));
    sram_write(0, fill, sizeof(fill));
}
