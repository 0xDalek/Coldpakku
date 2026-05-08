#ifndef BIP39_H
#define BIP39_H

#include <gba_types.h>
#include "pbkdf2.h"

/* Solo soportamos mnemonics de 12 palabras (128 bits entropy + 4 bits checksum). */

#define BIP39_WORDS_COUNT 12
#define BIP39_MAX_WORD_LEN 8         /* la palabra más larga del wordlist tiene 8 chars */
#define BIP39_MNEMONIC_MAX_LEN (BIP39_WORDS_COUNT * (BIP39_MAX_WORD_LEN + 1))

/* Devuelve el índice de 'word' en BIP39_WORDS o -1 si no existe. Búsqueda binaria. */
int  bip39_word_index(const char* word);

/* Cuenta cuántas palabras del wordlist empiezan por 'prefix'. Si <= max_out, escribe
 * sus índices en out_idx[]. Devuelve el conteo total (puede ser > max_out). */
u32  bip39_filter_prefix(const char* prefix, u32 max_out, u16* out_idx);

/* Devuelve 1 si existe alguna palabra BIP39 que empiece con `prefix`, 0
 * si no. Usado por la UI de teclado para evitar que el usuario itere
 * por letras que no producen ninguna palabra valida (ej. "cb", "qx"…). */
int  bip39_has_prefix(const char* prefix);

/* Valida el checksum de 12 palabras. Devuelve 1 si OK. */
int  bip39_validate_words(const u16 word_idx[BIP39_WORDS_COUNT]);

/* Construye la cadena mnemonic "word1 word2 ... word12" en out (siempre con
 * espacios entre palabras, sin trailing space). Devuelve la longitud. */
u32  bip39_build_mnemonic(const u16 word_idx[BIP39_WORDS_COUNT],
                          char out[BIP39_MNEMONIC_MAX_LEN]);

/* Deriva la seed BIP39 (64 bytes) desde mnemonic + passphrase usando PBKDF2-HMAC-SHA512
 * con 2048 iteraciones. Salt = "mnemonic" + passphrase. */
void bip39_mnemonic_to_seed(const char* mnemonic, u32 mlen,
                            const char* passphrase, u32 plen,
                            u8 seed[64],
                            pbkdf2_progress_fn progress, void* ud);

#endif
