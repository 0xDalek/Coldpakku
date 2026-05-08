#include "session.h"
#include "sram.h"
#include "../crypto/crypto.h"
#include "../crypto/hmac_sha256.h"
#include "sha256.h"

#include <string.h>

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

/* Deriva las dos claves desde el PIN: una para cifrar (ChaCha20) y otra
 * para autenticar (HMAC). Separación por dominio: byte 0x01 vs 0x02 en
 * el sufijo del input al SHA256. */
static void derive_keys(const char* pin, u32 pin_len,
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

/* Calcula el MAC sobre version || nonce(12) || enc_seed(64).
 * Se hace sobre version+nonce+ciphertext (encrypt-then-MAC) para autenticar
 * tambien la version (resistencia a downgrade) y el nonce. */
static void compute_mac(const u8 key_mac[32], const u8 blob[SESSION_BLOB_SIZE],
                        u8 mac[32]) {
    /* offset 4..81 = version(1) + nonce(12) + enc_seed(64) = 77 bytes */
    hmac_sha256(key_mac, 32, blob + 4, 1 + 12 + 64, mac);
}

int session_present(void) {
    u8 blob[SESSION_BLOB_SIZE];
    sram_read(0, blob, SESSION_BLOB_SIZE);
    if (memcmp(blob, SESSION_MAGIC, 4) != 0) return 0;
    if (blob[4] != SESSION_VERSION) return 0;
    u32 stored_crc = ((u32)blob[113]) | ((u32)blob[114] << 8)
                   | ((u32)blob[115] << 16) | ((u32)blob[116] << 24);
    u32 actual = crc32(blob, 113);
    return stored_crc == actual;
}

int session_save(const u8 seed[64], const char* pin, u32 pin_len) {
    u8 blob[SESSION_BLOB_SIZE];
    memset(blob, 0, sizeof(blob));
    memcpy(blob, SESSION_MAGIC, 4);
    blob[4] = SESSION_VERSION;
    crypto_fill_random(blob + 5, 12);

    u8 key_enc[32], key_mac[32];
    derive_keys(pin, pin_len, key_enc, key_mac);

    /* enc_seed = ChaCha20-XOR(seed, key_enc, nonce, ctr=0) */
    chacha20_xor(key_enc, blob + 5, 0, seed, blob + 17, 64);

    /* mac = HMAC-SHA256(key_mac, version || nonce || enc_seed) */
    compute_mac(key_mac, blob, blob + 81);

    /* CRC32 sobre todo lo anterior (proteccion contra corrupcion accidental
     * de SRAM, NO de seguridad — el MAC ya autentica) */
    u32 crc = crc32(blob, 113);
    blob[113] = (u8)(crc);
    blob[114] = (u8)(crc >> 8);
    blob[115] = (u8)(crc >> 16);
    blob[116] = (u8)(crc >> 24);

    sram_write(0, blob, SESSION_BLOB_SIZE);

    memset(key_enc, 0, sizeof(key_enc));
    memset(key_mac, 0, sizeof(key_mac));
    memset(blob, 0, sizeof(blob));
    return 1;
}

int session_load(const char* pin, u32 pin_len, u8 seed[64]) {
    if (!session_present()) return 0;

    u8 blob[SESSION_BLOB_SIZE];
    sram_read(0, blob, SESSION_BLOB_SIZE);

    u8 key_enc[32], key_mac[32];
    derive_keys(pin, pin_len, key_enc, key_mac);

    /* PRIMERO verifica el MAC. Si no cuadra, NO descifres ni devuelvas seed
     * basura — devuelve fallo para que el caller pida PIN otra vez. Esta es
     * la diferencia clave con v0x01 que devolvia 64 bytes de basura para
     * cualquier PIN. */
    u8 expected_mac[32];
    compute_mac(key_mac, blob, expected_mac);

    /* Comparacion en tiempo constante (anti timing-attack, aunque en GBA
     * no hay attacker remoto, es buena practica) */
    u32 diff = 0;
    for (int i = 0; i < 32; i++) diff |= (u32)(blob[81 + i] ^ expected_mac[i]);

    int ok = (diff == 0);
    if (ok) {
        chacha20_xor(key_enc, blob + 5, 0, blob + 17, seed, 64);
    }

    memset(key_enc, 0, sizeof(key_enc));
    memset(key_mac, 0, sizeof(key_mac));
    memset(expected_mac, 0, sizeof(expected_mac));
    memset(blob, 0, sizeof(blob));
    if (!ok) {
        memset(seed, 0, 64);
        return 0;
    }
    return 1;
}

void session_wipe(void) {
    u8 zero[SESSION_BLOB_SIZE];
    memset(zero, 0xFF, SESSION_BLOB_SIZE);
    sram_write(0, zero, SESSION_BLOB_SIZE);
}
