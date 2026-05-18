#include "rlp.h"

#include <string.h>

/* Reads a big-endian integer of n bytes (n in 1..8). */
static u64 read_be(const u8* p, u32 n) {
    u64 v = 0;
    for (u32 i = 0; i < n; i++) v = (v << 8) | p[i];
    return v;
}

int rlp_decode_item(const u8* buf, u32 buflen,
                    rlp_item* out, u32* consumed) {
    if (!buf || buflen == 0 || !out) return 0;
    u8 b0 = buf[0];

    /* short 1-byte string (b0 == that byte). */
    if (b0 <= 0x7f) {
        out->data    = buf;
        out->len     = 1;
        out->is_list = 0;
        if (consumed) *consumed = 1;
        return 1;
    }

    /* string with direct length: 0..55 */
    if (b0 <= 0xb7) {
        u32 len = b0 - 0x80;
        if (1u + len > buflen) return 0;
        /* canonicality: if len == 1, the byte must not be <= 0x7f
         * (otherwise it should have been encoded as a single byte) */
        if (len == 1 && buf[1] <= 0x7f) return 0;
        out->data    = buf + 1;
        out->len     = len;
        out->is_list = 0;
        if (consumed) *consumed = 1 + len;
        return 1;
    }

    /* long-length string: length-of-length prefix */
    if (b0 <= 0xbf) {
        u32 lol = b0 - 0xb7;            /* 1..8 */
        if (lol > 8 || 1u + lol > buflen) return 0;
        if (buf[1] == 0) return 0;       /* no leading zeros */
        u64 len = read_be(buf + 1, lol);
        if (len <= 55) return 0;         /* should be in the short branch */
        if (len > buflen - 1 - lol) return 0;
        out->data    = buf + 1 + lol;
        out->len     = (u32)len;
        out->is_list = 0;
        if (consumed) *consumed = 1 + lol + (u32)len;
        return 1;
    }

    /* list with direct length: 0..55 */
    if (b0 <= 0xf7) {
        u32 len = b0 - 0xc0;
        if (1u + len > buflen) return 0;
        out->data    = buf + 1;
        out->len     = len;
        out->is_list = 1;
        if (consumed) *consumed = 1 + len;
        return 1;
    }

    /* list with length-of-length */
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
    /* canonicality: no leading zeros (except the special case len==0
     * which represents zero) */
    if (item->len > 1 && item->data[0] == 0) return 0;
    /* the "empty string" 0x80 represents the integer 0 */
    u64 v = 0;
    for (u32 i = 0; i < item->len; i++) v = (v << 8) | item->data[i];
    *out = v;
    return 1;
}

int rlp_to_be_padded(const rlp_item* item, u8* out, u32 out_len) {
    if (!item || item->is_list) return 0;
    if (item->len > out_len) return 0;
    /* canonicality for integer-like: if the first byte is 0 and len>1,
     * it is mis-encoded. For purely "bytes" fields (data, address) it
     * doesn't apply, so we allow it. The caller decides. Here we only
     * validate length. */
    memset(out, 0, out_len);
    if (item->len > 0) {
        memcpy(out + (out_len - item->len), item->data, item->len);
    }
    return 1;
}
