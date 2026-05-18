#ifndef UI_INPUT_H
#define UI_INPUT_H

#include <gba_types.h>

/* Wrappers around scanKeys / keysDown / keysHeld. They keep the last
 * key-press timestamp (VBlank counter), useful as entropy. */

void input_init(void);
void input_poll(void);

u16 input_pressed(void);   /* edge: just pressed this frame */
u16 input_held(void);      /* level: held */
u16 input_released(void);

/* timestamp of the last state change (VBlank counter). */
u32 input_last_change_tick(void);

/* blocks until any key is pressed; returns the bitmask. */
u16 input_wait_any(void);

#endif
