#include "splash.h"
#include "splash_image.h"

#include <gba_video.h>
#include <gba_dma.h>
#include <gba_input.h>
#include <gba_interrupt.h>
#include <gba_systemcalls.h>
#include <string.h>

/*
 * Mode 4: BG2 with a 240x160 8bpp bitmap in VRAM (frame 0 at 0x06000000).
 * VRAM does not allow 8-bit writes => we copy as halfwords (u16).
 */

#define MODE4_FB ((u16 *)VRAM)

static void copy_pixels_dma(void) {
    /* DMA3 16-bit: 240*160/2 = 19200 halfwords. */
    DMA3COPY(SPLASH_PIXELS_HALF, MODE4_FB, (SPLASH_WIDTH * SPLASH_HEIGHT / 2) | DMA16);
}

static void load_palette(const u16 *src) {
    DMA3COPY(src, BG_PALETTE, 256 | DMA16);
}

/* Builds a "faded" version of the palette (step/total). */
static void fade_palette(u16 *out, u32 step, u32 total) {
    for (u32 i = 0; i < 256; i++) {
        u16 c = SPLASH_PALETTE[i];
        u32 r = (c >> 0)  & 0x1F;
        u32 g = (c >> 5)  & 0x1F;
        u32 b = (c >> 10) & 0x1F;
        r = (r * step) / total;
        g = (g * step) / total;
        b = (b * step) / total;
        out[i] = (u16)(r | (g << 5) | (b << 10));
    }
}

void splash_show(u32 max_frames) {
    u16 pal_buf[256];

    /* palette to black before switching mode, so no garbage is visible */
    memset(pal_buf, 0, sizeof(pal_buf));
    load_palette(pal_buf);

    REG_DISPCNT = MODE_4 | BG2_ON;

    copy_pixels_dma();

    /* fade-in: 16 steps */
    const u32 FADE_STEPS = 16;
    for (u32 step = 1; step <= FADE_STEPS; step++) {
        fade_palette(pal_buf, step, FADE_STEPS);
        load_palette(pal_buf);
        VBlankIntrWait();
        VBlankIntrWait();
    }

    /* final exact palette */
    load_palette((u16 *)SPLASH_PALETTE);

    /* hold + skip on any key */
    for (u32 frame = 0; frame < max_frames; frame++) {
        VBlankIntrWait();
        scanKeys();
        u16 down = keysDown();
        if (down) break;
    }

    /* fade-out (8 quick steps) */
    for (int step = (int)FADE_STEPS - 1; step >= 0; step -= 2) {
        fade_palette(pal_buf, (u32)step, FADE_STEPS);
        load_palette(pal_buf);
        VBlankIntrWait();
    }

    /* clear VRAM (mode 4 frame 0) and the palette to 0, so we don't
     * leave garbage when we go back to mode 0 with the libgba console */
    static const u16 zero = 0;
    REG_DMA3SAD = (u32)&zero;
    REG_DMA3DAD = (u32)MODE4_FB;
    REG_DMA3CNT = DMA_ENABLE | DMA_SRC_FIXED | DMA16 | (SPLASH_WIDTH * SPLASH_HEIGHT / 2);

    REG_DMA3SAD = (u32)&zero;
    REG_DMA3DAD = (u32)BG_PALETTE;
    REG_DMA3CNT = DMA_ENABLE | DMA_SRC_FIXED | DMA16 | 256;
}
