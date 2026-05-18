#include "eth_tx.h"
#include "rlp.h"
#include "keccak256.h"

#include <string.h>

static int parse_address(const rlp_item* it, u8 out[20], u8* has_to) {
    if (it->is_list) return 0;
    if (it->len == 0) {
        memset(out, 0, 20);
        *has_to = 0;
        return 1;
    }
    if (it->len != 20) return 0;
    memcpy(out, it->data, 20);
    *has_to = 1;
    return 1;
}

static int decode_1559_body(const u8* rlp_payload, u32 rlp_len, eth_tx* out) {
    rlp_item list;
    u32 consumed = 0;
    if (!rlp_decode_item(rlp_payload, rlp_len, &list, &consumed)) return 0;
    if (!list.is_list) return 0;

    rlp_iter it;
    rlp_iter_init(&list, &it);
    rlp_item field;

    if (!rlp_iter_next(&it, &field) || !rlp_to_u64(&field, &out->chainid)) return 0;
    if (!rlp_iter_next(&it, &field) || !rlp_to_u64(&field, &out->nonce))   return 0;
    if (!rlp_iter_next(&it, &field) || !rlp_to_u64(&field, &out->max_priority_fee_per_gas)) return 0;
    if (!rlp_iter_next(&it, &field) || !rlp_to_u64(&field, &out->max_fee_per_gas)) return 0;
    if (!rlp_iter_next(&it, &field) || !rlp_to_u64(&field, &out->gas_limit)) return 0;
    if (!rlp_iter_next(&it, &field) || !parse_address(&field, out->to, &out->has_to)) return 0;
    if (!rlp_iter_next(&it, &field) || !rlp_to_be_padded(&field, out->value_be, 32)) return 0;
    if (!rlp_iter_next(&it, &field) || field.is_list) return 0;
    out->data = field.data; out->data_len = field.len;
    /* accessList: a list; we consume it to validate but don't display it */
    if (!rlp_iter_next(&it, &field) || !field.is_list) return 0;
    /* after accessList there should be no more fields in an unsigned tx */
    if (!rlp_iter_eof(&it)) return 0;

    out->type = ETH_TX_TYPE_1559;
    return 1;
}

static int decode_legacy(const u8* raw, u32 raw_len, eth_tx* out) {
    rlp_item list;
    u32 consumed = 0;
    if (!rlp_decode_item(raw, raw_len, &list, &consumed)) return 0;
    if (!list.is_list) return 0;

    rlp_iter it;
    rlp_iter_init(&list, &it);
    rlp_item field;
    u64 gas_price = 0;

    if (!rlp_iter_next(&it, &field) || !rlp_to_u64(&field, &out->nonce))    return 0;
    if (!rlp_iter_next(&it, &field) || !rlp_to_u64(&field, &gas_price))     return 0;
    if (!rlp_iter_next(&it, &field) || !rlp_to_u64(&field, &out->gas_limit))return 0;
    if (!rlp_iter_next(&it, &field) || !parse_address(&field, out->to, &out->has_to)) return 0;
    if (!rlp_iter_next(&it, &field) || !rlp_to_be_padded(&field, out->value_be, 32)) return 0;
    if (!rlp_iter_next(&it, &field) || field.is_list) return 0;
    out->data = field.data; out->data_len = field.len;

    /* EIP-155: for an unsigned tx, the last 3 fields are [chainId, 0, 0].
     * If they are missing this is a pre-EIP-155 tx (chainid=0, not
     * recommended). */
    if (rlp_iter_next(&it, &field)) {
        if (!rlp_to_u64(&field, &out->chainid)) return 0;
        rlp_item r, s;
        if (!rlp_iter_next(&it, &r) || !rlp_iter_next(&it, &s)) return 0;
        u64 r_val = 0, s_val = 0;
        if (!rlp_to_u64(&r, &r_val) || !rlp_to_u64(&s, &s_val)) return 0;
        if (r_val != 0 || s_val != 0) return 0; /* we don't accept already-signed txs */
    } else {
        out->chainid = 0;
    }
    if (!rlp_iter_eof(&it)) return 0;

    out->max_fee_per_gas = gas_price;
    out->max_priority_fee_per_gas = 0;
    out->type = ETH_TX_TYPE_LEGACY;
    return 1;
}

int eth_tx_decode(const u8* raw, u32 raw_len, eth_tx* out) {
    if (!raw || raw_len < 1 || !out) return 0;
    memset(out, 0, sizeof(*out));
    out->raw     = raw;
    out->raw_len = raw_len;

    u8 b0 = raw[0];

    /* EIP-2718 envelope: if the first byte is in [0, 0x7f] it's a type byte. */
    if (b0 == 0x02) {
        return decode_1559_body(raw + 1, raw_len - 1, out);
    }
    if (b0 == 0x01) {
        /* EIP-2930 — not supported */
        return 0;
    }
    if (b0 < 0x80) {
        /* other reserved types or a stray single-byte string: not a legacy tx */
        return 0;
    }
    /* legacy: starts directly with the RLP list header (>= 0xc0) */
    if (b0 < 0xc0) return 0;
    return decode_legacy(raw, raw_len, out);
}

void eth_tx_signing_hash(const eth_tx* tx, u8 hash[32]) {
    /* Both formats: hash = keccak256 over the raw buffer (which
     * already includes the envelope for type 2 and the [chainId, 0, 0]
     * for legacy). */
    keccak256(tx->raw, tx->raw_len, hash);
}
