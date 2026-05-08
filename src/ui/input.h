#ifndef UI_INPUT_H
#define UI_INPUT_H

#include <gba_types.h>

/* Wrappers sobre scanKeys / keysDown / keysHeld. Mantienen el último
 * timestamp de pulsación en VBlank counter, útil para entropía. */

void input_init(void);
void input_poll(void);

u16 input_pressed(void);   /* edge: justo pulsado este frame */
u16 input_held(void);      /* nivel: mantenido */
u16 input_released(void);

/* timestamp del último cambio de estado (VBlank counter). */
u32 input_last_change_tick(void);

/* espera bloqueante hasta que se pulsa alguna tecla; devuelve la mascara. */
u16 input_wait_any(void);

#endif
