#ifndef UI_KEYBOARD_H
#define UI_KEYBOARD_H

#include <gba_types.h>
#include "../crypto/bip39.h"

/* Pide al usuario las 12 palabras BIP39 con teclado en pantalla y filtro
 * por prefijo. Bloquea hasta completar. Devuelve 1 si las 12 palabras
 * superan checksum BIP39, 0 si el usuario cancela. */
int keyboard_input_words(u16 out_idx[BIP39_WORDS_COUNT]);

#endif
