#ifndef SESSION_H
#define SESSION_H

#include <gba_types.h>
#include "../crypto/pbkdf2.h"   /* pbkdf2_progress_fn */

#define SESSION_MAGIC "GBAW"

/* Versions supported on READ:
 *   v2: legacy layout (KDF = single SHA256). Accepted so we don't lose
 *       sessions from existing users; when loading v2 we re-encrypt as
 *       v3 before returning, so a single unlock pays for the upgrade.
 *   v3: current layout (KDF = PBKDF2-HMAC-SHA512, random salt).
 *
 * On WRITE we always write v3.
 */
#define SESSION_VERSION_V2 0x02
#define SESSION_VERSION_V3 0x03
#define SESSION_VERSION_CURRENT SESSION_VERSION_V3

/* PBKDF2 iteration count for v3. Trade-off between unlock cost (~10s on
 * the GBA with HMAC-SHA512) and the cost for an attacker with a dumped
 * SRAM (10000x more expensive than v2). Adjust carefully: changing the
 * number invalidates existing sessions unless we store it in the blob
 * (we don't: v3 = 10000 fixed, blobs are self-describing by version not
 * by iters). */
#define SESSION_PBKDF2_ITERS_V3 10000u

/* SRAM layout at offset 0 for v3:
 *
 *   [0..4)     magic "GBAW"
 *   [4]        version (0x03)
 *   [5..21)    PBKDF2 salt    (16 bytes, random per save)
 *   [21..33)   ChaCha20 nonce (12 bytes, random per save)
 *   [33..97)   enc_seed = ChaCha20-XOR(seed, key_enc, nonce, ctr=0)
 *   [97..129)  HMAC-SHA256(key_mac, version || salt || nonce || enc_seed)
 *   [129..133) CRC32 over [0..129)
 *
 *   PBKDF2-HMAC-SHA512(PIN, salt, SESSION_PBKDF2_ITERS_V3) -> 64 bytes
 *   key_enc = bytes [0..32)   (ChaCha20 key)
 *   key_mac = bytes [32..64)  (HMAC key, domain separation comes for
 *                              free since both halves come from a single
 *                              PBKDF2 block)
 *
 *   Total: 133 bytes.
 *
 * v2 layout (legacy, read-only):
 *   [0..4)     magic
 *   [4]       version (0x02)
 *   [5..17)    nonce (12)
 *   [17..81)   enc_seed (64)
 *   [81..113)  HMAC (32)
 *   [113..117) CRC32 (4)
 *   key_enc = SHA256(PIN || 0x01)
 *   key_mac = SHA256(PIN || 0x02)
 */

#define SESSION_BLOB_SIZE      133   /* v3, what we reserve in SRAM */
#define SESSION_BLOB_SIZE_V2   117   /* legacy read-only */

/* Returns true if there is a valid blob in SRAM (magic + known version + CRC). */
int session_present(void);

/* Encrypts and stores the seed in SRAM with the given PIN.
 *  - progress may be NULL; if set, it is called during PBKDF2 to refresh UI.
 *  Returns 1 if OK. */
int session_save(const u8 seed[64], const char* pin, u32 pin_len,
                 pbkdf2_progress_fn progress, void* ud);

/* Reads blob, derives a key from the pin and decrypts the seed.
 *  Returns 1 if OK. If the blob was v2 and the PIN was correct it is
 *  rewritten as v3 before returning (a single unlock pays for the
 *  migration). */
int session_load(const char* pin, u32 pin_len, u8 seed[64],
                 pbkdf2_progress_fn progress, void* ud);

void session_wipe(void);

#endif
