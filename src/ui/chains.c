#include "chains.h"

/*
 * Static table of known networks. ORDER matters: the L/R selector on
 * the READY screen iterates this array linearly, so:
 *
 *   1) Mainnets ordered by popularity (Ethereum first, then the most-used
 *      L2s, then emerging L2s, then any relevant non-EVM mainnets).
 *   2) ALL testnets grouped at the end, marked with is_testnet=1 so the
 *      selector renders a " (test)" suffix and they're distinguishable
 *      at a glance. That way you never end up with the GBA locked to
 *      Sepolia while your dApp is on mainnet without it being obvious.
 *
 * Keep in sync with extension/src/lib/networks.ts. If you add a network
 * there and it's a common one, add it here too (with its icon); if it
 * is exotic, leave it out and the GBA will show the "GENERIC" icon +
 * chainId.
 *
 * NOTE: we no longer hard-code addresses of wrapped-natives
 * (WETH/WBNB/...). The extension queries symbol() / decimals() of the
 * `to:` contract via RPC and sends them with the tx in the meta block
 * (PROTO_TX_RLP_META). This lets us work with any dApp/contract without
 * recompiling the ROM every time a new wrapper, swap or token shows
 * up. */
/* `name` is capped at 11 chars so the chain selector on AWAITING
 * TRANSACTION fits with the label "  network   " + name <= 28 cols (the
 * screen is 30, we leave room for the arrows " >" at col 28-29). Longer
 * names use common abbreviations ("BNB Chain" instead of "BNB Smart
 * Chain", "Arb Sepolia" instead of "Arbitrum Sepolia"...). */
static const chain_info CHAINS[] = {
    /* === MAINNETS (ordered by TVL/popularity ~2026) ==================== */
    { 1,        "Ethereum",      "ETH",  "ETH",  0 },
    { 137,      "Polygon",       "POL",  "POL",  0 },
    { 8453,     "Base",          "BASE", "ETH",  0 },
    { 42161,    "Arbitrum",      "ARB",  "ETH",  0 },
    { 10,       "OP Mainnet",    "OP",   "ETH",  0 },
    { 56,       "BNB Chain",     "BNB",  "BNB",  0 },
    { 43114,    "Avalanche",     "AVAX", "AVAX", 0 },
    { 324,      "zkSync Era",    "ZK",   "ETH",  0 },
    { 59144,    "Linea",         "LIN",  "ETH",  0 },
    { 534352,   "Scroll",        "SCR",  "ETH",  0 },
    { 81457,    "Blast",         "BLST", "ETH",  0 },
    { 5000,     "Mantle",        "MNT",  "MNT",  0 },
    { 100,      "Gnosis",        "GNO",  "xDAI", 0 },

    /* === TESTNETS (all grouped at the end, is_testnet=1) =============== */
    { 11155111, "Sepolia",       "SEP",  "ETH",  1 },
    { 84532,    "Base Sepolia",  "BASE", "ETH",  1 },
    { 421614,   "Arb Sepolia",   "ARB",  "ETH",  1 },
    { 11155420, "OP Sepolia",    "OP",   "ETH",  1 },
    { 80002,    "Poly Amoy",     "POL",  "POL",  1 },
    { 97,       "BSC Testnet",   "tBNB", "tBNB", 1 },
};

#define CHAINS_COUNT  (sizeof(CHAINS) / sizeof(CHAINS[0]))

static const chain_info UNKNOWN_CHAIN = {
    0,                    /* chain_id is filled in at render time */
    "Custom network",
    "?",
    "ETH",                /* assume ETH as a reasonable fallback */
    0,                    /* we don't assume testnet */
};

const chain_info* chains_lookup(u32 chain_id) {
    for (u32 i = 0; i < CHAINS_COUNT; i++) {
        if (CHAINS[i].chain_id == chain_id) return &CHAINS[i];
    }
    return 0;
}

const chain_info* chains_unknown(void) {
    return &UNKNOWN_CHAIN;
}

u32 chains_count(void) {
    return (u32)CHAINS_COUNT;
}

const chain_info* chains_at(u32 idx) {
    if (idx >= CHAINS_COUNT) return 0;
    return &CHAINS[idx];
}

int chains_index_of(u32 chain_id) {
    for (u32 i = 0; i < CHAINS_COUNT; i++) {
        if (CHAINS[i].chain_id == chain_id) return (int)i;
    }
    return -1;
}
