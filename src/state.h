#ifndef STATE_H
#define STATE_H

#include <gba_types.h>

/* Entry point of the wallet logic. Call from main() after initializing
 * IRQs / console. Never returns unless a fatal error occurs. */
void wallet_run(void);

#endif
