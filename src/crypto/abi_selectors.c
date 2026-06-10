#include "abi_selectors.h"

/*
 * Selector table. Selectors verified with `cast sig 'name(types)'` (or
 * the equivalent keccak256 of the canonical signature). All entries use
 * ABI_T_END only at compile-time inside the args arrays; the num_args
 * field is what the decoder iterates against (we don't rely on the
 * sentinel at runtime, but keeping it makes the arrays self-checking).
 *
 * Adding a new entry:
 *   1. Verify the selector: `cast sig 'doStuff(address,uint256)'`.
 *   2. Pick arg names that the user will recognise on a 30-col screen.
 *   3. Add the args array (static const) above the table.
 *   4. Append the entry to ABI_KNOWN_FUNCS.
 *   5. Done. ABI_KNOWN_FUNCS_COUNT computes itself from sizeof.
 */

/* ---------------- ERC-20 ---------------- */

static const abi_arg_t ARGS_TRANSFER[] = {
    { "to",     ABI_T_ADDRESS },
    { "amount", ABI_T_UINT256 },
    { 0, ABI_T_END },
};

static const abi_arg_t ARGS_APPROVE[] = {
    { "spender", ABI_T_ADDRESS },
    { "amount",  ABI_T_UINT256 },
    { 0, ABI_T_END },
};

static const abi_arg_t ARGS_TRANSFER_FROM[] = {
    { "from",   ABI_T_ADDRESS },
    { "to",     ABI_T_ADDRESS },
    { "amount", ABI_T_UINT256 },
    { 0, ABI_T_END },
};

static const abi_arg_t ARGS_MINT[] = {
    { "to",     ABI_T_ADDRESS },
    { "amount", ABI_T_UINT256 },
    { 0, ABI_T_END },
};

static const abi_arg_t ARGS_BURN[] = {
    { "amount", ABI_T_UINT256 },
    { 0, ABI_T_END },
};

/* ---------------- ERC-721 / ERC-1155 ---------------- */

static const abi_arg_t ARGS_SAFE_TRANSFER_FROM[] = {
    { "from",    ABI_T_ADDRESS },
    { "to",      ABI_T_ADDRESS },
    { "tokenId", ABI_T_UINT256 },
    { 0, ABI_T_END },
};

static const abi_arg_t ARGS_SAFE_TRANSFER_FROM_DATA[] = {
    { "from",    ABI_T_ADDRESS },
    { "to",      ABI_T_ADDRESS },
    { "tokenId", ABI_T_UINT256 },
    { "data",    ABI_T_BYTES   },
    { 0, ABI_T_END },
};

static const abi_arg_t ARGS_SET_APPROVAL_FOR_ALL[] = {
    { "operator", ABI_T_ADDRESS },
    { "approved", ABI_T_BOOL    },
    { 0, ABI_T_END },
};

/* ---------------- WETH ---------------- */

/* deposit() has no args; the table entry just has num_args = 0. */

static const abi_arg_t ARGS_WITHDRAW[] = {
    { "amount", ABI_T_UINT256 },
    { 0, ABI_T_END },
};

/* ---------------- ERC-2612 Permit (sendTransaction path) ---------------- */

static const abi_arg_t ARGS_PERMIT[] = {
    { "owner",    ABI_T_ADDRESS },
    { "spender",  ABI_T_ADDRESS },
    { "value",    ABI_T_UINT256 },
    { "deadline", ABI_T_DEADLINE_UINT256 },
    { "v",        ABI_T_UINT8   },
    { "r",        ABI_T_BYTES32 },
    { "s",        ABI_T_BYTES32 },
    { 0, ABI_T_END },
};

/* ---------------- Uniswap V2 router ---------------- */

/* swapExactETHForTokens(amountOutMin, path, to, deadline) — spend tx.value
 * ETH, receive at least amountOutMin of the last token in path. */
static const abi_arg_t ARGS_SWAP_EXACT_ETH_FOR_TOKENS[] = {
    { "amountOutMin", ABI_T_UINT256 },
    { "path",         ABI_T_ADDRESS_ARRAY },
    { "to",           ABI_T_ADDRESS },
    { "deadline",     ABI_T_DEADLINE_UINT256 },
    { 0, ABI_T_END },
};

/* swapETHForExactTokens(amountOut, path, to, deadline) — spend up to
 * tx.value, receive exactly amountOut of the last token in path. */
static const abi_arg_t ARGS_SWAP_ETH_FOR_EXACT_TOKENS[] = {
    { "amountOut",   ABI_T_UINT256 },
    { "path",        ABI_T_ADDRESS_ARRAY },
    { "to",          ABI_T_ADDRESS },
    { "deadline",    ABI_T_DEADLINE_UINT256 },
    { 0, ABI_T_END },
};

/* swapExactTokensFor* family (5 args): amountIn fixed, amountOutMin
 * minimum acceptable. Used by swapExactTokensForETH and
 * swapExactTokensForTokens. */
static const abi_arg_t ARGS_SWAP_EXACT_TOKENS_FOR[] = {
    { "amountIn",     ABI_T_UINT256 },
    { "amountOutMin", ABI_T_UINT256 },
    { "path",         ABI_T_ADDRESS_ARRAY },
    { "to",           ABI_T_ADDRESS },
    { "deadline",     ABI_T_DEADLINE_UINT256 },
    { 0, ABI_T_END },
};

/* swapTokensForExact* family (5 args): amountOut fixed, amountInMax
 * is the upper bound on what's spent. Used by swapTokensForExactETH
 * and swapTokensForExactTokens. */
static const abi_arg_t ARGS_SWAP_TOKENS_FOR_EXACT[] = {
    { "amountOut",   ABI_T_UINT256 },
    { "amountInMax", ABI_T_UINT256 },
    { "path",        ABI_T_ADDRESS_ARRAY },
    { "to",          ABI_T_ADDRESS },
    { "deadline",    ABI_T_DEADLINE_UINT256 },
    { 0, ABI_T_END },
};

static const abi_arg_t ARGS_ADD_LIQUIDITY_ETH[] = {
    { "token",          ABI_T_ADDRESS },
    { "amountTokenDes", ABI_T_UINT256 },
    { "amountTokenMin", ABI_T_UINT256 },
    { "amountETHMin",   ABI_T_UINT256 },
    { "to",             ABI_T_ADDRESS },
    { "deadline",       ABI_T_DEADLINE_UINT256 },
    { 0, ABI_T_END },
};

static const abi_arg_t ARGS_ADD_LIQUIDITY[] = {
    { "tokenA",      ABI_T_ADDRESS },
    { "tokenB",      ABI_T_ADDRESS },
    { "amountADes",  ABI_T_UINT256 },
    { "amountBDes",  ABI_T_UINT256 },
    { "amountAMin",  ABI_T_UINT256 },
    { "amountBMin",  ABI_T_UINT256 },
    { "to",          ABI_T_ADDRESS },
    { "deadline",    ABI_T_DEADLINE_UINT256 },
    { 0, ABI_T_END },
};

static const abi_arg_t ARGS_REMOVE_LIQUIDITY[] = {
    { "tokenA",     ABI_T_ADDRESS },
    { "tokenB",     ABI_T_ADDRESS },
    { "liquidity",  ABI_T_UINT256 },
    { "amountAMin", ABI_T_UINT256 },
    { "amountBMin", ABI_T_UINT256 },
    { "to",         ABI_T_ADDRESS },
    { "deadline",   ABI_T_DEADLINE_UINT256 },
    { 0, ABI_T_END },
};

static const abi_arg_t ARGS_REMOVE_LIQUIDITY_ETH[] = {
    { "token",        ABI_T_ADDRESS },
    { "liquidity",    ABI_T_UINT256 },
    { "amountTokMin", ABI_T_UINT256 },
    { "amountETHMin", ABI_T_UINT256 },
    { "to",           ABI_T_ADDRESS },
    { "deadline",     ABI_T_DEADLINE_UINT256 },
    { 0, ABI_T_END },
};

/* ---------------- Wrapper-style: multicall + Universal Router ---------------- */

static const abi_arg_t ARGS_MULTICALL_BYTES[] = {
    { "calls", ABI_T_BYTES_ARRAY_SUB_COUNT },
    { 0, ABI_T_END },
};

static const abi_arg_t ARGS_MULTICALL_DEADLINE[] = {
    { "deadline", ABI_T_DEADLINE_UINT256 },
    { "calls",    ABI_T_BYTES_ARRAY_SUB_COUNT },
    { 0, ABI_T_END },
};

static const abi_arg_t ARGS_UNIROUTER_EXECUTE[] = {
    { "commands", ABI_T_BYTES_SUB_COUNT },
    { "inputs",   ABI_T_BYTES_ARRAY_SUB_COUNT },
    { "deadline", ABI_T_DEADLINE_UINT256 },
    { 0, ABI_T_END },
};

static const abi_arg_t ARGS_UNIROUTER_EXECUTE_NODEADLINE[] = {
    { "commands", ABI_T_BYTES_SUB_COUNT },
    { "inputs",   ABI_T_BYTES_ARRAY_SUB_COUNT },
    { 0, ABI_T_END },
};

/* ---------------- The table ---------------- */

const abi_known_fn_t ABI_KNOWN_FUNCS[] = {
    /* ERC-20 */
    { 0xa9059cbb, "transfer",     ARGS_TRANSFER,        2, ABI_FN_FLAG_NONE    },
    { 0x095ea7b3, "approve",      ARGS_APPROVE,         2, ABI_FN_FLAG_DRAINER },
    { 0x23b872dd, "transferFrom", ARGS_TRANSFER_FROM,   3, ABI_FN_FLAG_NONE    },
    { 0x40c10f19, "mint",         ARGS_MINT,            2, ABI_FN_FLAG_NONE    },
    { 0x42966c68, "burn",         ARGS_BURN,            1, ABI_FN_FLAG_NONE    },

    /* ERC-721 / ERC-1155 */
    { 0x42842e0e, "safeTransferFrom",     ARGS_SAFE_TRANSFER_FROM,      3, ABI_FN_FLAG_NONE    },
    { 0xb88d4fde, "safeTransferFromData", ARGS_SAFE_TRANSFER_FROM_DATA, 4, ABI_FN_FLAG_NONE    },
    { 0xa22cb465, "setApprovalForAll",    ARGS_SET_APPROVAL_FOR_ALL,    2, ABI_FN_FLAG_DRAINER },

    /* WETH */
    { 0xd0e30db0, "deposit",  0,             0, ABI_FN_FLAG_NONE },
    { 0x2e1a7d4d, "withdraw", ARGS_WITHDRAW, 1, ABI_FN_FLAG_NONE },

    /* ERC-2612 Permit */
    { 0xd505accf, "permit", ARGS_PERMIT, 7, ABI_FN_FLAG_DRAINER },

    /* Uniswap V2 router */
    { 0x7ff36ab5, "swapExactETHForTokens",    ARGS_SWAP_EXACT_ETH_FOR_TOKENS, 4, ABI_FN_FLAG_NONE },
    { 0x18cbafe5, "swapExactTokensForETH",    ARGS_SWAP_EXACT_TOKENS_FOR,     5, ABI_FN_FLAG_NONE },
    { 0x38ed1739, "swapExactTokensForTokens", ARGS_SWAP_EXACT_TOKENS_FOR,     5, ABI_FN_FLAG_NONE },
    { 0x4a25d94a, "swapTokensForExactETH",    ARGS_SWAP_TOKENS_FOR_EXACT,     5, ABI_FN_FLAG_NONE },
    { 0xfb3bdb41, "swapETHForExactTokens",    ARGS_SWAP_ETH_FOR_EXACT_TOKENS, 4, ABI_FN_FLAG_NONE },
    { 0x8803dbee, "swapTokensForExactTokens", ARGS_SWAP_TOKENS_FOR_EXACT,     5, ABI_FN_FLAG_NONE },
    { 0xf305d719, "addLiquidityETH",                ARGS_ADD_LIQUIDITY_ETH,            6, ABI_FN_FLAG_NONE },
    { 0xe8e33700, "addLiquidity",                   ARGS_ADD_LIQUIDITY,                8, ABI_FN_FLAG_NONE },
    { 0xbaa2abde, "removeLiquidity",                ARGS_REMOVE_LIQUIDITY,             7, ABI_FN_FLAG_NONE },
    { 0x02751cec, "removeLiquidityETH",             ARGS_REMOVE_LIQUIDITY_ETH,         6, ABI_FN_FLAG_NONE },

    /* Wrappers (multicall + Universal Router) */
    { 0xac9650d8, "multicall",       ARGS_MULTICALL_BYTES,            1, ABI_FN_FLAG_WRAPPER },
    { 0x5ae401dc, "multicallDeadln", ARGS_MULTICALL_DEADLINE,         2, ABI_FN_FLAG_WRAPPER },
    { 0x3593564c, "execute",         ARGS_UNIROUTER_EXECUTE,          3, ABI_FN_FLAG_WRAPPER },
    { 0x24856bc3, "executeNoDeadln", ARGS_UNIROUTER_EXECUTE_NODEADLINE, 2, ABI_FN_FLAG_WRAPPER },
};

const u32 ABI_KNOWN_FUNCS_COUNT =
    sizeof(ABI_KNOWN_FUNCS) / sizeof(ABI_KNOWN_FUNCS[0]);

const abi_known_fn_t* abi_lookup_selector(const u8 selector[4]) {
    /* Compose into a single u32 BE so we compare ints, not byte-by-byte. */
    u32 sel = ((u32)selector[0] << 24) | ((u32)selector[1] << 16)
            | ((u32)selector[2] << 8)  | (u32)selector[3];
    for (u32 i = 0; i < ABI_KNOWN_FUNCS_COUNT; i++) {
        if (ABI_KNOWN_FUNCS[i].selector_be == sel) {
            return &ABI_KNOWN_FUNCS[i];
        }
    }
    return 0;
}
