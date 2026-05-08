#include "rlp.h"

#include <string.h>

/* Lee un entero big-endian de n bytes (n in 1..8). */
static u64 read_be(const u8* p, u32 n) {
    u64 v = 0;
    for (u32 i = 0; i < n; i++) v = (v << 8) | p[i];
    return v;
}

int rlp_decode_item(const u8* buf, u32 buflen,
                    rlp_item* out, u32* consumed) {
    if (!buf || buflen == 0 || !out) return 0;
    u8 b0 = buf[0];

    /* string corto de 1 byte (b0 == ese byte). */
    if (b0 <= 0x7f) {
        out->data    = buf;
        out->len     = 1;
        out->is_list = 0;
        if (consumed) *consumed = 1;
        return 1;
    }

    /* string de longitud directa: 0..55 */
    if (b0 <= 0xb7) {
        u32 len = b0 - 0x80;
        if (1u + len > buflen) return 0;
        /* canonicalidad: si len == 1, el byte no debe ser <= 0x7f
         * (porque entonces se debería haber codificado como single byte) */
        if (len == 1 && buf[1] <= 0x7f) return 0;
        out->data    = buf + 1;
        out->len     = len;
        out->is_list = 0;
        if (consumed) *consumed = 1 + len;
        return 1;
    }

    /* string de longitud larga: prefijo de length-of-length */
    if (b0 <= 0xbf) {
        u32 lol = b0 - 0xb7;            /* 1..8 */
        if (lol > 8 || 1u + lol > buflen) return 0;
        if (buf[1] == 0) return 0;       /* sin leading zeros */
        u64 len = read_be(buf + 1, lol);
        if (len <= 55) return 0;         /* debería estar en rama corta */
        if (len > buflen - 1 - lol) return 0;
        out->data    = buf + 1 + lol;
        out->len     = (u32)len;
        out->is_list = 0;
        if (consumed) *consumed = 1 + lol + (u32)len;
        return 1;
    }

    /* lista de longitud directa: 0..55 */
    if (b0 <= 0xf7) {
        u32 len = b0 - 0xc0;
        if (1u + len > buflen) return 0;
        out->data    = buf + 1;
        out->len     = len;
        out->is_list = 1;
        if (consumed) *consumed = 1 + len;
        return 1;
    }

    /* lista con length-of-length */
    {
        u32 lol = b0 - 0xf7;             /* 1..8 */
        if (lol > 8 || 1u + lol > buflen) return 0;
        if (buf[1] == 0) return 0;
        u64 len = read_be(buf + 1, lol);
        if (len <= 55) return 0;
        if (len > buflen - 1 - lol) return 0;
        out->data    = buf + 1 + lol;
        out->len     = (u32)len;
        out->is_list = 1;
        if (consumed) *consumed = 1 + lol + (u32)len;
        return 1;
    }
}

void rlp_iter_init(const rlp_item* list, rlp_iter* it) {
    it->p   = list->data;
    it->end = list->data + list->len;
}

int rlp_iter_eof(const rlp_iter* it) {
    return it->p >= it->end;
}

int rlp_iter_next(rlp_iter* it, rlp_item* out) {
    if (it->p >= it->end) return 0;
    u32 consumed = 0;
    if (!rlp_decode_item(it->p, (u32)(it->end - it->p), out, &consumed)) return 0;
    it->p += consumed;
    return 1;
}

int rlp_to_u64(const rlp_item* item, u64* out) {
    if (!item || item->is_list) return 0;
    if (item->len > 8) return 0;
    /* canonicalidad: no leading zeros (excepto el caso especial de len==0
     * que representa el cero) */
    if (item->len > 1 && item->data[0] == 0) return 0;
    /* el "string vacío" 0x80 representa el entero 0 */
    u64 v = 0;
    for (u32 i = 0; i < item->len; i++) v = (v << 8) | item->data[i];
    *out = v;
    return 1;
}

int rlp_to_be_padded(const rlp_item* item, u8* out, u32 out_len) {
    if (!item || item->is_list) return 0;
    if (item->len > out_len) return 0;
    /* canonicalidad para integer-like: si el primer byte es 0 y len>1,
     * está mal codificado. Para campos puramente "bytes" (data, address)
     * no aplica, así que lo permitimos. El caller decide.
     * Aquí solo validamos longitud. */
    memset(out, 0, out_len);
    if (item->len > 0) {
        memcpy(out + (out_len - item->len), item->data, item->len);
    }
    return 1;
}
