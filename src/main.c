/*
 * Coldpakku — entry point.
 *
 * Minimal libgba init and delegates to wallet_run() (state.c).
 */
#include "state.h"

#include <gba_console.h>
#include <gba_interrupt.h>
#include <gba_video.h>

int main(void) {
    /* Mode 0 with BG0 for the console; consoleDemoInit configures
     * everything inside text_init() via libgba. */
    wallet_run();
    return 0;
}
