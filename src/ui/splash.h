#ifndef UI_SPLASH_H
#define UI_SPLASH_H

#include "../types.h"

/*
 * Title screen: paints the COLDPAKKU cartridge image in mode 4 (240x160
 * 8bpp paletted bitmap), waits N frames or a key press, then restores
 * text mode (mode 0 + libgba console).
 *
 * IMPORTANT: after calling splash_show() you must call text_init() again
 * (or equivalent) to be able to use text_at/text_clear/etc.
 */
void splash_show(u32 max_frames);

#endif
