#ifndef CRYPTO_ETH_TX_H
#define CRYPTO_ETH_TX_H

#include "../types.h"

/*
 * Ethereum transaction decoder.
 *
 * Supports:
 *   - Legacy (type 0): plain RLP [nonce, gasPrice, gasLimit, to, value,
 *                                 data, chainId, 0, 0]
 *   - EIP-1559 (type 2): envelope 0x02 || RLP[chainId, nonce,
 *                       maxPriorityFeePerGas, maxFeePerGas, gasLimit,
 *                       to, value, data, accessList]
 *
 * What is NOT supported:
 *   - EIP-2930 (type 1) — rare, will be added if it shows up
 *   - access list content — we walk it but don't display it
 *   - chainId that doesn't fit in u64 (rare, every chain fits)
 *   - value > 2^256 (structurally impossible if the sender respects RLP)
 *
 * Buffers `to`, `value_be` are flattened to 20/32 BE bytes. `data`
 * points inside the original RLP buffer (zero-copy).
 */

#define ETH_TX_TYPE_LEGACY  0
#define ETH_TX_TYPE_1559    2

typedef struct {
    u8  type;                       /* 0 legacy, 2 EIP-1559 */
    u64 chainid;
    u64 nonce;

    /* gas pricing: for legacy gas_price = max_fee_per_gas and
     * max_priority_fee_per_gas = 0 (we normalise it that way). */
    u64 max_priority_fee_per_gas;
    u64 max_fee_per_gas;

    u64 gas_limit;

    u8  has_to;                     /* 0 = contract creation */
    u8  to[20];

    u8  value_be[32];               /* big-endian, padded */

    const u8* data;
    u32 data_len;

    /* meta for hashing: pointers into the original buffer */
    const u8* raw;
    u32 raw_len;
} eth_tx;

/* Parses a serialised transaction. raw can be:
 *   - [0x02, ...] EIP-1559
 *   - [0x01, ...] EIP-2930 (returns 0, not supported)
 *   - [< 0x80] or other: legacy (plain RLP list)
 *
 * Returns 1 on ok, 0 if malformed or an unsupported type. */
int eth_tx_decode(const u8* raw, u32 raw_len, eth_tx* out);

/* Computes the hash that is signed (signing hash):
 *   - Legacy:    keccak256(rlp([nonce, gasPrice, gasLimit, to, value, data,
 *                               chainId, 0, 0]))
 *                   = keccak256(raw)  because it already arrives RLP-encoded
 *   - EIP-1559: keccak256(0x02 || rlp([chainId, nonce, maxPFee, maxFee,
 *                                       gas, to, value, data, accessList]))
 *                   = keccak256(raw)  because raw already includes the 0x02
 *
 * In both cases keccak256(raw_complete) is enough. */
void eth_tx_signing_hash(const eth_tx* tx, u8 hash[32]);

#endif
