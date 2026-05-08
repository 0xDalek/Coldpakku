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
    /* accessList: lista, la consumimos para validar pero no la mostramos */
    if (!rlp_iter_next(&it, &field) || !field.is_list) return 0;
    /* tras accessList no debe haber más campos en una unsigned tx */
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

    /* EIP-155: para tx sin firmar, los últimos 3 campos son [chainId, 0, 0].
     * Si no están, es una tx pre-EIP-155 (chainid=0, no recomendado). */
    if (rlp_iter_next(&it, &field)) {
        if (!rlp_to_u64(&field, &out->chainid)) return 0;
        rlp_item r, s;
        if (!rlp_iter_next(&it, &r) || !rlp_iter_next(&it, &s)) return 0;
        u64 r_val = 0, s_val = 0;
        if (!rlp_to_u64(&r, &r_val) || !rlp_to_u64(&s, &s_val)) return 0;
        if (r_val != 0 || s_val != 0) return 0; /* no aceptamos tx ya firmadas */
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

    /* envelope EIP-2718: si el primer byte está en [0, 0x7f] es un type byte. */
    if (b0 == 0x02) {
        return decode_1559_body(raw + 1, raw_len - 1, out);
    }
    if (b0 == 0x01) {
        /* EIP-2930 — no soportado */
        return 0;
    }
    if (b0 < 0x80) {
        /* otros types reservados o single-byte string suelto: no es tx legacy */
        return 0;
    }
    /* legacy: empieza directamente con la cabecera de lista RLP (>= 0xc0) */
    if (b0 < 0xc0) return 0;
    return decode_legacy(raw, raw_len, out);
}

void eth_tx_signing_hash(const eth_tx* tx, u8 hash[32]) {
    /* Ambos formatos: hash = keccak256 sobre el buffer raw (que ya
     * incluye el envelope para type 2 y los [chainId, 0, 0] para legacy). */
    keccak256(tx->raw, tx->raw_len, hash);
}
