#ifndef UI_KEYBOARD_H
#define UI_KEYBOARD_H

#include <gba_types.h>
#include "../crypto/bip39.h"

/* Asks the user for the 12 BIP-39 words via an on-screen keyboard with
 * a prefix filter. Blocks until completion. Returns 1 if the 12 words
 * pass the BIP-39 checksum, 0 if the user cancels. */
int keyboard_input_words(u16 out_idx[BIP39_WORDS_COUNT]);

#endif
