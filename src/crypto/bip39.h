#ifndef BIP39_H
#define BIP39_H

#include <gba_types.h>
#include "pbkdf2.h"

/* We only support 12-word mnemonics (128 bits entropy + 4 bits checksum). */

#define BIP39_WORDS_COUNT 12
#define BIP39_MAX_WORD_LEN 8         /* longest word in the wordlist is 8 chars */
#define BIP39_MNEMONIC_MAX_LEN (BIP39_WORDS_COUNT * (BIP39_MAX_WORD_LEN + 1))

/* Returns the index of `word` in BIP39_WORDS, or -1 if absent. Binary
 * search. */
int  bip39_word_index(const char* word);

/* Counts how many wordlist entries start with `prefix`. If <= max_out,
 * writes their indices into out_idx[]. Returns the total count (can be
 * > max_out). */
u32  bip39_filter_prefix(const char* prefix, u32 max_out, u16* out_idx);

/* Returns 1 if there is any BIP-39 word starting with `prefix`, 0
 * otherwise. Used by the keyboard UI to prevent iterating through
 * letters that produce no valid word (e.g. "cb", "qx"...). */
int  bip39_has_prefix(const char* prefix);

/* Validates the checksum of 12 words. Returns 1 if OK. */
int  bip39_validate_words(const u16 word_idx[BIP39_WORDS_COUNT]);

/* Builds the mnemonic string "word1 word2 ... word12" in `out` (always
 * with spaces between words, no trailing space). Returns the length. */
u32  bip39_build_mnemonic(const u16 word_idx[BIP39_WORDS_COUNT],
                          char out[BIP39_MNEMONIC_MAX_LEN]);

/* Derives the BIP-39 seed (64 bytes) from mnemonic + passphrase using
 * PBKDF2-HMAC-SHA512 with 2048 iterations. Salt = "mnemonic" +
 * passphrase. */
void bip39_mnemonic_to_seed(const char* mnemonic, u32 mlen,
                            const char* passphrase, u32 plen,
                            u8 seed[64],
                            pbkdf2_progress_fn progress, void* ud);

#endif
