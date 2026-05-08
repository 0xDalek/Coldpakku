#ifndef UI_PIN_H
#define UI_PIN_H

#include <gba_types.h>

#define PIN_MIN_LEN 4
#define PIN_MAX_LEN 8

/* Pide un PIN de PIN_MIN_LEN-PIN_MAX_LEN dígitos al usuario.
 * D-pad arriba/abajo cambia el dígito en la posición actual,
 * izq/derecha mueve la posición, A confirma, B borra el último.
 * Devuelve longitud del PIN, o 0 si el usuario cancela (START).
 *
 * El PIN sale en out como ASCII '0'-'9' (sin terminador). */
u32 pin_input(char out[PIN_MAX_LEN], const char* prompt);

#endif
