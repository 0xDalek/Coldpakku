#ifndef CRYPTO_RLP_H
#define CRYPTO_RLP_H

#include "../types.h"

/*
 * RLP (Recursive Length Prefix) decoder — Yellow Paper Appendix B.
 *
 * Design:
 *   - Zero-copy: rlp_item.data points inside the original buffer, no
 *     allocation.
 *   - No recursion: the iterator descends into lists explicitly.
 *   - Tolerates arbitrary input without OOB (every size is validated
 *     against the total buffer).
 *
 * Format (summary):
 *   byte b0:
 *     0x00..0x7f       1-byte string = b0
 *     0x80..0xb7       string of len = b0-0x80 (0..55 bytes)
 *     0xb8..0xbf       string of len = u(b0-0xb7) BE bytes
 *     0xc0..0xf7       list with payload = b0-0xc0 (0..55 bytes)
 *     0xf8..0xff       list with len = u(b0-0xf7) BE bytes
 */

typedef struct {
    const u8* data;     /* pointer to the PAYLOAD (not the header) */
    u32       len;      /* payload length */
    u8        is_list;  /* 1 if list, 0 if bytes/string */
} rlp_item;

typedef struct {
    const u8* p;
    const u8* end;
} rlp_iter;

/* Decodes ONE item from buf. Returns 1 on ok, 0 if malformed.
 * If consumed != NULL, writes how many bytes the header+payload took. */
int rlp_decode_item(const u8* buf, u32 buflen,
                    rlp_item* out, u32* consumed);

/* Initialises an iterator over the payload of a list. */
void rlp_iter_init(const rlp_item* list, rlp_iter* it);

/* Consumes the next item in the list. 0 = end or error. Distinguishes
 * "end" (ok, no bytes left) from "error" (corrupted data): use
 * rlp_iter_eof() to check. */
int rlp_iter_next(rlp_iter* it, rlp_item* out);
int rlp_iter_eof(const rlp_iter* it);

/* Helpers to convert a bytes item into an unsigned integer. Returns 0
 * if the item is not interpretable as uintN (length > N bytes, or
 * leading zeros, which are not allowed in RLP integers). */
int rlp_to_u64(const rlp_item* item, u64* out);

/* Copies a bytes item to out with left-padding up to out_len. Useful
 * for fields like `value` (uint256) that get serialised minimally in
 * RLP but we want as a 32-byte big-endian buffer. Returns 0 if
 * item->len > out_len. */
int rlp_to_be_padded(const rlp_item* item, u8* out, u32 out_len);

#endif
