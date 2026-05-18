#include "tx_meta.h"

#include <string.h>

/* Copies up to `max` bytes from `src` to `dst`, replacing
 * non-printable characters with '?'. Guarantees '\0' termination
 * at dst[max]. */
static void copy_safe_ascii(char* dst, u32 max, const u8* src, u32 src_len) {
    u32 n = src_len < max ? src_len : max;
    for (u32 i = 0; i < n; i++) {
        u8 c = src[i];
        dst[i] = (c >= 0x20 && c < 0x7F) ? (char)c : '?';
    }
    dst[n] = '\0';
}

void tx_meta_init(tx_meta* m) {
    if (!m) return;
    memset(m, 0, sizeof(*m));
}

int tx_meta_parse(const u8* blob, u32 blob_len, tx_meta* out) {
    if (!out) return 0;
    if (!blob || blob_len == 0) return 1;   /* empty meta is valid */

    u32 i = 0;
    while (i < blob_len) {
        /* Each TLV: type(1) + len(1) + value(len). We need at least
         * 2 bytes to read the header. */
        if (i + 2 > blob_len) return 0;
        u8 type = blob[i++];
        u8 vlen = blob[i++];
        if (i + vlen > blob_len) return 0;   /* truncated TLV: reject */

        switch (type) {
        case META_TYPE_ORIGIN:
            if (vlen <= META_ORIGIN_MAX) {
                copy_safe_ascii(out->origin, META_ORIGIN_MAX, blob + i, vlen);
                out->has_origin = 1;
            }
            /* else: invalid length -> ignore but keep parsing */
            break;

        case META_TYPE_TO_NAME:
            if (vlen <= META_NAME_MAX) {
                copy_safe_ascii(out->to_name, META_NAME_MAX, blob + i, vlen);
                out->has_to_name = 1;
            }
            break;

        case META_TYPE_TO_SYMBOL:
            if (vlen <= META_SYMBOL_MAX) {
                copy_safe_ascii(out->to_symbol, META_SYMBOL_MAX, blob + i, vlen);
                out->has_to_symbol = 1;
            }
            break;

        case META_TYPE_TO_DECIMALS:
            /* uint256 max is 78 digits (~10^78); cap at a sane bound */
            if (vlen == 1 && blob[i] <= 77) {
                out->to_decimals = blob[i];
                out->has_to_decimals = 1;
            }
            break;

        default:
            /* unknown type: silent skip (forward-compat) */
            break;
        }

        i += vlen;
    }
    return 1;
}
