#include "eth_abi.h"

#include <string.h>

/* Selectors (first 4 bytes of keccak256("name(types)")). Verified with
 * `cast sig 'transfer(address,uint256)'` etc. */
static const u8 SEL_TRANSFER[4]              = { 0xa9, 0x05, 0x9c, 0xbb };
static const u8 SEL_APPROVE[4]               = { 0x09, 0x5e, 0xa7, 0xb3 };
static const u8 SEL_TRANSFER_FROM[4]         = { 0x23, 0xb8, 0x72, 0xdd };
static const u8 SEL_SAFE_TRANSFER_FROM[4]    = { 0x42, 0x84, 0x2e, 0x0e };
static const u8 SEL_SET_APPROVAL_FOR_ALL[4]  = { 0xa2, 0x2c, 0xb4, 0x65 };
/* WETH9 wrap/unwrap. The amount for deposit comes in tx.value (empty
 * data, selector only); for withdraw it comes in the single uint256
 * arg. */
static const u8 SEL_WETH_DEPOSIT[4]          = { 0xd0, 0xe3, 0x0d, 0xb0 };
static const u8 SEL_WETH_WITHDRAW[4]         = { 0x2e, 0x1a, 0x7d, 0x4d };

static int sel_eq(const u8* data, const u8 sel[4]) {
    return data[0] == sel[0] && data[1] == sel[1]
        && data[2] == sel[2] && data[3] == sel[3];
}

/* Reads a 32-byte ABI slot starting at offset and interprets it as an
 * address. If the 12 top padding bytes are not 0, fails (the data is
 * "dirty" — we'd rather not sign than risk misinterpreting). */
static int read_address(const u8* data, u32 offset, u8 out[20]) {
    for (u32 i = 0; i < 12; i++) {
        if (data[offset + i] != 0) return 0;
    }
    memcpy(out, data + offset + 12, 20);
    return 1;
}

/* Copies a uint256 slot (32 bytes) verbatim. The ABI already delivers
 * it big-endian, exactly the format the rest of the code uses. */
static void read_uint256(const u8* data, u32 offset, u8 out[32]) {
    memcpy(out, data + offset, 32);
}

/* Reads an ABI bool: 31 bytes 0x00 + 1 byte strictly 0x00 or 0x01.
 * Returns 1 if valid and *out_bool with the value; 0 if malformed. */
static int read_bool(const u8* data, u32 offset, u8* out_bool) {
    for (u32 i = 0; i < 31; i++) {
        if (data[offset + i] != 0) return 0;
    }
    u8 b = data[offset + 31];
    if (b != 0 && b != 1) return 0;
    *out_bool = b;
    return 1;
}

static int is_max_uint256(const u8 v[32]) {
    for (u32 i = 0; i < 32; i++) {
        if (v[i] != 0xFF) return 0;
    }
    return 1;
}

int eth_abi_decode(const u8* data, u32 data_len, eth_abi_call* out) {
    if (!data || !out || data_len < 4) return 0;
    memset(out, 0, sizeof(*out));

    /* deposit(): selector only, no args = 4 bytes */
    if (data_len == 4) {
        if (sel_eq(data, SEL_WETH_DEPOSIT)) {
            out->kind = ETH_ABI_WETH_DEPOSIT;
            return 1;
        }
        return 0;
    }

    /* withdraw(uint256): selector + 1 slot = 36 bytes */
    if (data_len == 36) {
        if (sel_eq(data, SEL_WETH_WITHDRAW)) {
            read_uint256(data, 4, out->value_be);
            out->kind = ETH_ABI_WETH_WITHDRAW;
            return 1;
        }
        return 0;
    }

    /* transfer / approve / setApprovalForAll: selector + 2 slots = 68 bytes */
    if (data_len == 68) {
        if (sel_eq(data, SEL_TRANSFER)) {
            if (!read_address(data, 4, out->addr_a)) return 0;
            read_uint256(data, 36, out->value_be);
            out->kind = ETH_ABI_ERC20_TRANSFER;
            return 1;
        }
        if (sel_eq(data, SEL_APPROVE)) {
            if (!read_address(data, 4, out->addr_a)) return 0;
            read_uint256(data, 36, out->value_be);
            out->is_infinite = (u8)is_max_uint256(out->value_be);
            out->kind = ETH_ABI_ERC20_APPROVE;
            return 1;
        }
        if (sel_eq(data, SEL_SET_APPROVAL_FOR_ALL)) {
            if (!read_address(data, 4, out->addr_a)) return 0;
            if (!read_bool(data, 36, &out->approved_bool)) return 0;
            /* value_be stays at 0; the bool is exposed via approved_bool */
            out->kind = ETH_ABI_SET_APPROVAL_FOR_ALL;
            return 1;
        }
        return 0;
    }

    /* transferFrom / safeTransferFrom: selector + 3 slots = 100 bytes */
    if (data_len == 100) {
        if (sel_eq(data, SEL_TRANSFER_FROM)) {
            if (!read_address(data, 4,  out->addr_a)) return 0;
            if (!read_address(data, 36, out->addr_b)) return 0;
            read_uint256(data, 68, out->value_be);
            out->has_addr_b = 1;
            out->kind = ETH_ABI_TRANSFER_FROM;
            return 1;
        }
        if (sel_eq(data, SEL_SAFE_TRANSFER_FROM)) {
            if (!read_address(data, 4,  out->addr_a)) return 0;
            if (!read_address(data, 36, out->addr_b)) return 0;
            read_uint256(data, 68, out->value_be);
            out->has_addr_b = 1;
            out->kind = ETH_ABI_SAFE_TRANSFER_FROM;
            return 1;
        }
        return 0;
    }

    return 0;
}
