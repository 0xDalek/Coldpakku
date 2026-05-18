#ifndef UI_PIN_H
#define UI_PIN_H

#include <gba_types.h>

#define PIN_MIN_LEN 4
#define PIN_MAX_LEN 8

/* Asks the user for a PIN of PIN_MIN_LEN-PIN_MAX_LEN digits.
 * D-pad up/down changes the digit at the current position, left/right
 * moves the position, A confirms, B deletes the last digit.
 * Returns the PIN length, or 0 if the user cancels (START).
 *
 * The PIN is written to `out` as ASCII '0'-'9' (no terminator). */
u32 pin_input(char out[PIN_MAX_LEN], const char* prompt);

#endif
