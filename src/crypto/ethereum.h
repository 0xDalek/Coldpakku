#ifndef ETHEREUM_H
#define ETHEREUM_H

#include <gba_types.h>

/* Calcula la dirección Ethereum (20 bytes) a partir de la priv key (32 bytes).
 * pubkey: keccak256(pub_uncompressed_64)[12..32] = address.
 * Si out_pubkey != NULL, también lo escribe ahí (64 bytes, sin prefijo 04).
 */
int eth_priv_to_address(const u8 priv[32], u8 address[20], u8 out_pubkey[64]);

/* Firma determinista RFC 6979 sobre un hash de 32 bytes. Devuelve r||s||v.
 * v = 27 + recid (estilo legacy Ethereum, ajustable a EIP-155 fuera de aquí).
 * Devuelve 1 si OK, 0 si falla. */
int eth_sign_hash(const u8 priv[32], const u8 hash[32], u8 sig[65]);

/* Recupera la dirección a partir de hash + sig (compat sanidad). Devuelve 1 si
 * la firma es válida y la address recuperada coincide con expected_addr. */
int eth_verify_recover(const u8 hash[32], const u8 sig[65], const u8 expected_addr[20]);

/* Formatea una dirección como string EIP-55 con checksum mixto.
 * out debe tener al menos 43 bytes ("0x" + 40 hex + NUL). */
void eth_address_to_eip55(const u8 address[20], char out[43]);

#endif
