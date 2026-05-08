#ifndef CRYPTO_ETH_TX_H
#define CRYPTO_ETH_TX_H

#include "../types.h"

/*
 * Decoder de transacciones Ethereum.
 *
 * Soporta:
 *   - Legacy (type 0): RLP plano [nonce, gasPrice, gasLimit, to, value,
 *                                 data, chainId, 0, 0]
 *   - EIP-1559 (type 2): envelope 0x02 || RLP[chainId, nonce,
 *                       maxPriorityFeePerGas, maxFeePerGas, gasLimit,
 *                       to, value, data, accessList]
 *
 * Lo que NO se soporta:
 *   - EIP-2930 (type 1) — raro, lo añadiremos si aparece
 *   - access list contenido — la atravesamos pero no la mostramos
 *   - chainId que no quepa en u64 (raro, todos los chains caben)
 *   - value > 2^256 (estructuralmente imposible si el remitente respeta RLP)
 *
 * Los buffers `to`, `value_be` se aplanan a 20/32 bytes BE.
 * `data` apunta dentro del buffer RLP original (zero-copy).
 */

#define ETH_TX_TYPE_LEGACY  0
#define ETH_TX_TYPE_1559    2

typedef struct {
    u8  type;                       /* 0 legacy, 2 EIP-1559 */
    u64 chainid;
    u64 nonce;

    /* gas pricing: para legacy gas_price = max_fee_per_gas y
     * max_priority_fee_per_gas = 0 (lo normalizamos así). */
    u64 max_priority_fee_per_gas;
    u64 max_fee_per_gas;

    u64 gas_limit;

    u8  has_to;                     /* 0 = contract creation */
    u8  to[20];

    u8  value_be[32];               /* big-endian, padded */

    const u8* data;
    u32 data_len;

    /* meta para hashing: punteros al buffer original */
    const u8* raw;
    u32 raw_len;
} eth_tx;

/* Parsea una transacción serializada. raw puede ser:
 *   - [0x02, ...] EIP-1559
 *   - [0x01, ...] EIP-2930 (devuelve 0, no soportado)
 *   - [< 0x80] u otro: legacy (lista RLP directa)
 *
 * Devuelve 1 ok, 0 si malformed o tipo no soportado. */
int eth_tx_decode(const u8* raw, u32 raw_len, eth_tx* out);

/* Calcula el hash que se firma (signing hash):
 *   - Legacy:    keccak256(rlp([nonce, gasPrice, gasLimit, to, value, data,
 *                               chainId, 0, 0]))
 *                   = keccak256(raw)  porque ya viene RLP-encoded
 *   - EIP-1559: keccak256(0x02 || rlp([chainId, nonce, maxPFee, maxFee,
 *                                       gas, to, value, data, accessList]))
 *                   = keccak256(raw)  porque raw ya incluye el 0x02
 *
 * En ambos casos basta keccak256(raw_completo). */
void eth_tx_signing_hash(const eth_tx* tx, u8 hash[32]);

#endif
