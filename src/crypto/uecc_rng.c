/*
 * Wrapper to register our RNG (based on the GBA's hardware timers) as
 * micro-ecc's default RNG. RFC 6979 removes the need for an RNG on the
 * critical path, but micro-ecc still requires one as an
 * anti-side-channel measure in sign_deterministic; any noise (not
 * necessarily cryptographic) is enough.
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
