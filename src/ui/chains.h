#ifndef UI_CHAINS_H
#define UI_CHAINS_H

#include "../types.h"

/*
 * Registry of known EVM networks. Used only for rendering: human-readable
 * name, abbreviation (3-4 chars) and native symbol. The signing logic
 * works with the raw `chainId` and does NOT depend on this table. If the
 * extension sends an unknown chainId (a custom network added via
 * wallet_addEthereumChain), the GBA falls back to "Custom network" and
 * shows just the number.
 */

typedef struct {
    u32  chain_id;
    const char* name;        /* up to ~22 chars: "Ethereum Mainnet"  */
    const char* abbr;        /* 3-4 chars: "ETH", "POL", "BASE"      */
    const char* native_sym;  /* 3-4 chars: "ETH", "POL", "BNB", ...  */
    u8   is_testnet;         /* 1 if testnet (Sepolia, Amoy, ...).
                                * The selector renders it with a "(test)"
                                * suffix so it can't be confused with
                                * mainnet. */
} chain_info;

/* Note: the wrapped-native (WETH/WBNB/WMATIC/...) is NOT hard-coded here.
 * It is identified via metadata the host (extension) attaches to the tx
 * with PROTO_TX_RLP_META (origin, to_name, to_symbol, to_decimals). Any
 * dApp with any wrapped-token works without recompiling the ROM. See
 * src/link/tx_meta.h. */

/* Returns the chain_info for chain_id, or NULL if not registered. */
const chain_info* chains_lookup(u32 chain_id);

/* Fallback with GENERIC icon and "?" abbr for unknown chains. Never
 * returns NULL: if chains_lookup() returns NULL, call this instead. */
const chain_info* chains_unknown(void);

/* Number of chains in the registry (does not include the "unknown"
 * fallback). */
u32 chains_count(void);

/* Index access. idx in [0..chains_count()). Returns NULL if out of
 * range. Networks are ordered by "reasonable popularity" (mainnet
 * first, L2s, then testnets) — see chains.c. */
const chain_info* chains_at(u32 idx);

/* Returns the index of chain_id in the registry, or -1 if not present.
 * Useful to initialise the READY screen selector from the policy. */
int chains_index_of(u32 chain_id);

#endif
