#ifndef SESSION_H
#define SESSION_H

#include <gba_types.h>

#define SESSION_MAGIC "GBAW"
#define SESSION_VERSION 0x02

/* Layout en SRAM offset 0:
 *
 *   [0..4)     magic "GBAW"
 *   [4]        version 0x02 (v1: ChaCha20-XOR sin MAC -> permitia silently
 *              firmar con wallet random si el PIN era incorrecto. v2 anade
 *              HMAC-SHA256 sobre el ciphertext para autenticar el PIN).
 *   [5..17)    nonce ChaCha20 (12 bytes, random por sesion)
 *   [17..81)   enc_seed = ChaCha20-XOR(seed, key_enc, nonce, ctr=0)  (64 bytes)
 *   [81..113)  HMAC-SHA256(key_mac, version || nonce || enc_seed)    (32 bytes)
 *   [113..117) CRC32 sobre [0..113)
 *
 *   key_enc = SHA256(PIN || 0x01)   (clave para ChaCha20)
 *   key_mac = SHA256(PIN || 0x02)   (clave para HMAC, separada por dominio)
 *
 *   Total: 117 bytes.
 *
 * NOTA: blobs v0x01 son INCOMPATIBLES con esta version y se descartan; el
 * usuario tendra que volver a meter la seed. Es una migracion forzada
 * porque el formato viejo era inseguro: cualquier PIN derivaba "una"
 * wallet (basura), confundiendo al usuario.
 */

#define SESSION_BLOB_SIZE 117

/* Comprueba si hay un blob válido en SRAM (magic + CRC). */
int session_present(void);

/* Cifra y guarda la seed en SRAM con el PIN dado. Devuelve 1 si OK. */
int session_save(const u8 seed[64], const char* pin, u32 pin_len);

/* Lee blob, deriva clave desde pin y descifra seed. Devuelve 1 si OK. */
int session_load(const char* pin, u32 pin_len, u8 seed[64]);

void session_wipe(void);

#endif
