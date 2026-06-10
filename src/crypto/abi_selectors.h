#ifndef CRYPTO_ABI_SELECTORS_H
#define CRYPTO_ABI_SELECTORS_H

#include "../types.h"

/*
 * Table of known function selectors (first 4 bytes of
 * keccak256("name(types)")) so the GBA can decode the calldata of an
 * eth_sendTransaction on-device, the same way it parses EIP-712 on-device
 * since v0.2. The table is hardcoded in ROM (no host-side hints) so a
 * compromised browser cannot mislabel a "transfer()" as an "approve()".
 *
 * Scope (v0.3): atomic ABI types only.
 *   - Recognised: address, bool, uint*, int*, bytesN, bytes, string,
 *     address[] (used in Uniswap V2 swap paths).
 *   - Wrappers (multicall / execute) are flagged with ABI_T_SUB_COUNT
 *     so the UI can show "N sub-commands" without descending into the
 *     inner bytes/bytes[] payload. Per-protocol decoders for those
 *     payloads (Universal Router commands, etc.) are v0.4.
 *   - ABI tuples and the V3 mint/exactInput* family are intentionally
 *     OUT of scope: they cannot be safely decoded without their full
 *     ABI and we'd rather fall back to blind-sign than guess.
 *
 * If the selector is not in this table the UI falls back to the legacy
 * hex view, identical to v0.2 behaviour.
 */

/* All atomic types we know how to render. Keep the enum compact so each
 * abi_arg_t is small (selector tables are duplicated in ROM). */
typedef enum {
    ABI_T_END = 0,           /* sentinel for the end of an args array */

    /* Static atomic types (1 ABI slot = 32 bytes each, big-endian). */
    ABI_T_ADDRESS,           /* 20 bytes + 12 B zero-padding (LE12) */
    ABI_T_BOOL,              /* 1 byte (0 or 1) + 31 B zero-padding (LE31) */
    ABI_T_UINT8,
    ABI_T_UINT16,
    ABI_T_UINT24,
    ABI_T_UINT32,
    ABI_T_UINT48,
    ABI_T_UINT64,
    ABI_T_UINT128,
    ABI_T_UINT160,
    ABI_T_UINT256,
    ABI_T_INT256,
    ABI_T_BYTES4,
    ABI_T_BYTES32,

    /* Dynamic atomic types (head is a 32 B offset, payload at offset). */
    ABI_T_BYTES,             /* dynamic bytes; UI shows short hex preview */
    ABI_T_STRING,            /* dynamic UTF-8; UI shows truncated string */
    ABI_T_ADDRESS_ARRAY,     /* dynamic address[]; UI shows "N: 0x.. -> 0x.." */

    /* Hints for wrapper functions. The decoder still consumes the slot
     * (head pointer + length prefix at the payload) but the UI shows
     * "N sub-commands" instead of trying to render the inner blob. */
    ABI_T_BYTES_SUB_COUNT,   /* dynamic bytes; shown as "N sub-commands" */
    ABI_T_BYTES_ARRAY_SUB_COUNT, /* dynamic bytes[]; shown as "N sub-commands" */

    /* Semantic aliases of static types. Same wire encoding as their base
     * type, different rendering hint. */
    ABI_T_DEADLINE_UINT256,  /* uint256 Unix timestamp; UI may show "~Xm left" */
} abi_type_t;

typedef struct {
    const char* name;        /* arg name: "spender", "amount", "deadline" */
    abi_type_t  type;
} abi_arg_t;

typedef struct {
    u32              selector_be;   /* first 4 bytes of keccak256(sig), BE */
    const char*      func_name;     /* "approve", "transfer", ... */
    const abi_arg_t* args;          /* array of args (terminated by ABI_T_END) */
    u8               num_args;
    u8               flags;         /* reserved (see ABI_FN_FLAG_*) */
} abi_known_fn_t;

/* Flags. */
#define ABI_FN_FLAG_NONE       0x00
#define ABI_FN_FLAG_WRAPPER    0x01  /* function is multicall/execute-like
                                      * (has ABI_T_BYTES*_SUB_COUNT args) */
#define ABI_FN_FLAG_DRAINER    0x02  /* setApprovalForAll, approve(infinite)
                                      * level of danger - UI may emphasize */

/* The full table, defined in abi_selectors.c. Iterate with
 * ABI_KNOWN_FUNCS_COUNT. */
extern const abi_known_fn_t ABI_KNOWN_FUNCS[];
extern const u32 ABI_KNOWN_FUNCS_COUNT;

/* Looks up the entry whose selector matches the first 4 bytes of `data`.
 * Returns NULL if there is no match (caller falls back to hex view).
 * Linear scan: ~30 entries, completes in <1 ms on the ARM7TDMI. */
const abi_known_fn_t* abi_lookup_selector(const u8 selector[4]);

#endif
