#ifndef BIP32_H
#define BIP32_H

#include <gba_types.h>

#define BIP32_HARDENED 0x80000000UL

typedef struct {
    u8 priv[32];
    u8 chain[32];
} bip32_node;

/* Master key desde seed BIP39 (64 bytes). */
void bip32_master(const u8 seed[64], bip32_node* out);

/* Derivación CKD en sitio: in se sustituye por el hijo en out (o reemplaza in si out == in).
 * Si index >= BIP32_HARDENED es hardened. Devuelve 1 si OK, 0 si falla. */
int  bip32_ckd(const bip32_node* in, u32 index, bip32_node* out);

/* Conveniencia: deriva m/44'/60'/0'/0/0 (path estándar Ethereum). */
int  bip32_derive_eth_default(const bip32_node* master, bip32_node* out);

#endif
