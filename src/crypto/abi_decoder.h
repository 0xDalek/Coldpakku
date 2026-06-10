#ifndef CRYPTO_ABI_DECODER_H
#define CRYPTO_ABI_DECODER_H

#include "../types.h"
#include "abi_selectors.h"

/*
 * Generic ABI head/tail decoder for the atomic subset we support
 * (see abi_selectors.h). Given the raw calldata bytes (selector
 * included) and a known function entry from the selector table,
 * walks the head/tail layout and produces a flat list of decoded
 * values ready to render on the confirm screen.
 *
 * Memory model:
 *   - No allocations. Caller provides an `abi_decoded_t` with a
 *     fixed-size args array (ABI_DECODED_MAX_ARGS).
 *   - For dynamic types (bytes/string/address[]/sub-count) the
 *     decoded representation is a (length, pointer-into-calldata)
 *     pair so we never copy bulk data.
 *   - Caller MUST keep the `data` pointer valid for the lifetime of
 *     the decoded struct.
 *
 * On any decoding error (truncation, out-of-bounds, non-zero pad
 * bytes, malformed offsets) the function returns the appropriate
 * ABI_DEC_ERR_* status and the UI falls back to the hex view.
 */

#define ABI_DECODED_MAX_ARGS  8   /* per function; matches the largest
                                   * entry in abi_selectors.c (addLiquidity = 8) */

typedef enum {
    ABI_DEC_OK = 0,
    ABI_DEC_ERR_NO_SELECTOR,    /* data_len < 4 */
    ABI_DEC_ERR_UNKNOWN_SEL,    /* selector not in ABI_KNOWN_FUNCS */
    ABI_DEC_ERR_TRUNCATED,      /* calldata shorter than the head expects */
    ABI_DEC_ERR_BAD_PAD,        /* high padding bytes != 0 (dirty slot) */
    ABI_DEC_ERR_BAD_OFFSET,     /* dynamic offset out of range or unaligned */
    ABI_DEC_ERR_TOO_MANY_ARGS,  /* fn has more args than ABI_DECODED_MAX_ARGS */
    ABI_DEC_ERR_UNSUP_TYPE,     /* selector matched but uses a type we cannot
                                 * render (e.g. mid-row tuple snuck in) */
} abi_dec_status_t;

/* Decoded representation of a single argument. The shape depends on
 * type; the union members below are alternatives, not all live at once. */
typedef struct {
    abi_type_t type;          /* copy from abi_arg_t for convenience */
    union {
        /* Static atomic. For uintN/intN/bytesN/bytes32 we keep the
         * raw 32-byte ABI slot exactly as the wire delivered it;
         * formatters in the UI know how to extract the meaningful
         * bytes per type. bool is rendered from raw[31]. */
        u8 raw[32];

        /* Dynamic: bytes / string / address[] / sub_count hints. */
        struct {
            u32 count;        /* element count (for arrays) or byte len */
            const u8* ptr;    /* points into the original calldata payload
                               * (NOT into raw[]); valid only while the
                               * caller keeps `data` alive */
        } dyn;
    } v;
} abi_decoded_arg_t;

typedef struct {
    const abi_known_fn_t* fn;            /* matched table entry */
    u32                   num_args;      /* mirrors fn->num_args */
    abi_decoded_arg_t     args[ABI_DECODED_MAX_ARGS];
} abi_decoded_t;

/* Decodes `data` (calldata, including the 4-byte selector). Returns
 * ABI_DEC_OK on success and fills *out. On error *out is left in an
 * undefined state; out->fn is reset to NULL so the caller can also
 * use `out->fn != NULL` as a success check. */
abi_dec_status_t abi_decode(const u8* data, u32 data_len, abi_decoded_t* out);

#endif
