/*
 * GBA Signer — entry point.
 *
 * Inicializa libgba mínimo y delega en wallet_run() (state.c).
 */
#include "state.h"

#include <gba_console.h>
#include <gba_interrupt.h>
#include <gba_video.h>

int main(void) {
    /* Modo 0 con BG0 para consola; consoleDemoInit ya configura todo
     * dentro de text_init() vía libgba. */
    wallet_run();
    return 0;
}
