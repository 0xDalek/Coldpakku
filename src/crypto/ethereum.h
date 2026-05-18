#ifndef ETHEREUM_H
#define ETHEREUM_H

#include <gba_types.h>

/* Computes the Ethereum address (20 bytes) from the priv key (32 bytes).
 * pubkey: keccak256(pub_uncompressed_64)[12..32] = address.
 * If out_pubkey != NULL, also writes it there (64 bytes, no 04 prefix).
 */
int eth_priv_to_address(const u8 priv[32], u8 address[20], u8 out_pubkey[64]);

/* RFC 6979 deterministic signature over a 32-byte hash. Returns r||s||v.
 * v = 27 + recid (legacy Ethereum style, adjustable for EIP-155 outside
 * this function). Returns 1 on success, 0 on failure. */
int eth_sign_hash(const u8 priv[32], const u8 hash[32], u8 sig[65]);

/* Recovers the address from hash + sig (compat / sanity). Returns 1 if
 * the signature is valid and the recovered address matches
 * expected_addr. */
int eth_verify_recover(const u8 hash[32], const u8 sig[65], const u8 expected_addr[20]);

/* Formats an address as an EIP-55 mixed-case checksum string.
 * `out` must have at least 43 bytes ("0x" + 40 hex + NUL). */
void eth_address_to_eip55(const u8 address[20], char out[43]);

#endif
