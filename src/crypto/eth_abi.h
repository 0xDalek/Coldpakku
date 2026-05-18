#ifndef CRYPTO_ETH_ABI_H
#define CRYPTO_ETH_ABI_H

#include "../types.h"

/*
 * Decoder of known ABI selectors over a tx's `data` field.
 *
 * We recognise 5 functions that cover the bulk of dangerous mainnet/L2
 * interactions:
 *
 *   ERC-20:
 *     - transfer(address,uint256)             0xa9059cbb
 *     - approve(address,uint256)              0x095ea7b3
 *     - transferFrom(address,address,uint256) 0x23b872dd  *
 *
 *   ERC-721 / ERC-1155 (subset):
 *     - safeTransferFrom(addr,addr,uint256)   0x42842e0e
 *     - setApprovalForAll(address,bool)       0xa22cb465  ** drainer-grade
 *
 *   * `transferFrom` with the same selector is used by both ERC-20 and
 *     ERC-721. We cannot distinguish them from data alone; the value of
 *     the 3rd argument is interpreted as "amount" (ERC-20) or "tokenId"
 *     (ERC-721) depending on the contract's context. The screen shows
 *     the raw value and the user decides based on the `to:` contract
 *     (already visible on the header page).
 *
 *   ** `setApprovalForAll(operator, true)` grants `operator` permission
 *     to transfer ALL the NFTs in the collection. It's the most common
 *     drainer pattern in NFT collections — must stand out on screen.
 *
 * Validations:
 *   - len(data) matches the signature exactly (transfer/approve: 68;
 *     transferFrom/safeTransferFrom: 100; setApprovalForAll: 68).
 *   - The 12 bytes of zero-padding before each address are 0.
 *   - The bool argument of setApprovalForAll is strictly 0 or 1.
 *
 * We don't show partially-decoded parameters: if anything doesn't fit
 * the caller falls back to a generic hex dump ("don't guess, don't
 * blind-sign").
 */

#define ETH_ABI_UNKNOWN              0
#define ETH_ABI_ERC20_TRANSFER       1   /* transfer(to, value) */
#define ETH_ABI_ERC20_APPROVE        2   /* approve(spender, value) */
#define ETH_ABI_TRANSFER_FROM        3   /* transferFrom(from, to, value/tokenId) */
#define ETH_ABI_SAFE_TRANSFER_FROM   4   /* safeTransferFrom(from, to, tokenId) */
#define ETH_ABI_SET_APPROVAL_FOR_ALL 5   /* setApprovalForAll(operator, approved) */
#define ETH_ABI_WETH_DEPOSIT         6   /* deposit() — wrap native (uses tx.value) */
#define ETH_ABI_WETH_WITHDRAW        7   /* withdraw(uint256) — unwrap native */

typedef struct {
    u8  kind;            /* one of ETH_ABI_* */

    /* Decoded addresses. The meaning depends on `kind`:
     *   TRANSFER:        addr_a = to,        addr_b = unused
     *   APPROVE:         addr_a = spender,   addr_b = unused
     *   TRANSFER_FROM:   addr_a = from,      addr_b = to
     *   SAFE_TRANSFER:   addr_a = from,      addr_b = to
     *   SET_APPROVAL:    addr_a = operator,  addr_b = unused
     */
    u8  addr_a[20];
    u8  addr_b[20];
    u8  has_addr_b;      /* 1 if addr_b is used, 0 otherwise */

    /* Big-endian uint256 value. Meaning:
     *   TRANSFER / APPROVE:        amount (in the token's smallest unit)
     *   TRANSFER_FROM:             amount or tokenId (ambiguous, see header)
     *   SAFE_TRANSFER_FROM:        tokenId
     *   SET_APPROVAL_FOR_ALL:      0x...01 (true) or 0x...00 (false)
     */
    u8  value_be[32];

    /* Flags derived from value_be, computed here so the UI doesn't have
     * to re-scan: */
    u8  is_infinite;     /* APPROVE with value == 2^256 - 1 */
    u8  approved_bool;   /* SET_APPROVAL_FOR_ALL: 0 = revoke, 1 = grant */
} eth_abi_call;

/* Parses `data` (the bytes after and including the selector).
 * Returns 1 if recognised and all fields validate; 0 otherwise
 * (including data_len < 4 or unknown selector).
 *
 * On 0, the contents of *out are undefined — the caller must fall back
 * to the generic hex render. */
int eth_abi_decode(const u8* data, u32 data_len, eth_abi_call* out);

#endif
