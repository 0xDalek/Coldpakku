/*
 * Wrapper para registrar nuestro RNG (basado en timers HW del GBA) como RNG
 * por defecto de micro-ecc. RFC 6979 elimina la necesidad de RNG en el
 * camino crítico, pero micro-ecc sigue exigiendo uno como anti-side-channel
 * en sign_deterministic; cualquier ruido (no necesariamente seguro) sirve.
 */
#include "uECC.h"
#include "crypto.h"

static int rng(uint8_t* dest, unsigned size) {
    crypto_fill_random(dest, size);
    return 1;
}

void uecc_register_rng(void) {
    uECC_set_rng(&rng);
}
