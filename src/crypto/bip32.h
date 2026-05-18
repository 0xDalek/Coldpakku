#ifndef BIP32_H
#define BIP32_H

#include <gba_types.h>

#define BIP32_HARDENED 0x80000000UL

typedef struct {
    u8 priv[32];
    u8 chain[32];
} bip32_node;

/* Master key from the BIP-39 seed (64 bytes). */
void bip32_master(const u8 seed[64], bip32_node* out);

/* In-place CKD derivation: `in` is replaced by the child in `out` (or
 * replaces in if out == in). If index >= BIP32_HARDENED it is hardened.
 * Returns 1 on success, 0 on failure. */
int  bip32_ckd(const bip32_node* in, u32 index, bip32_node* out);

/* Convenience: derives m/44'/60'/0'/0/0 (the standard Ethereum path). */
int  bip32_derive_eth_default(const bip32_node* master, bip32_node* out);

/* Progress callback for BIP-32 derivation. `done` goes from 1 to `total`
 * (5 steps in m/44'/60'/0'/0/0). `ud` is opaque user data. */
typedef void (*bip32_progress_fn)(u32 done, u32 total, void* ud);

/* Same as bip32_derive_eth_default but calls the callback after each
 * of the 5 ckd's. Useful to show a progress bar in the UI. If `cb` is
 * NULL, behaves like bip32_derive_eth_default. */
int  bip32_derive_eth_default_progress(const bip32_node* master,
                                       bip32_node* out,
                                       bip32_progress_fn cb,
                                       void* ud);

#endif
