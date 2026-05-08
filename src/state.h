#ifndef STATE_H
#define STATE_H

#include <gba_types.h>

/* Punto de entrada de la lógica de la wallet. Llama desde main() después
 * de inicializar IRQs / consola. Nunca retorna salvo en error fatal. */
void wallet_run(void);

#endif
