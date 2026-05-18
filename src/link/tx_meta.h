#ifndef LINK_TX_META_H
#define LINK_TX_META_H

#include "../types.h"
#include "protocol.h"   /* META_*_MAX */

/*
 * Informational metadata the host attaches to a tx via PROTO_TX_RLP_META.
 *
 * These fields are NOT crypto-verifiable — the GBA only displays them as
 * "host says X" on CONFIRM TX so the user has context about where the
 * request comes from. The signature is still computed over the raw RLP
 * bytes, so any host lie is immediately visible when compared against
 * the `to:`, `value`, `data` parsed on-device.
 *
 * The pattern is equivalent to EIP-712 typed_data: the host pretty-prints
 * a human-readable text so the user can decide, and the GBA verifies the
 * hash independently.
 *
 * Parser validations (tx_meta_parse):
 *   - Each TLV consumes exactly `len` bytes; if it exceeds the blob -> fail
 *   - Strings: 0x20..0x7E (visible ASCII) or 0x09 (tab) — everything else
 *     is replaced with '?' on copy so the render cannot be broken and
 *     control codes cannot be injected into the screen.
 *   - TO_DECIMALS: range 0..77 (the uint256 max has 78 digits)
 *   - Unknown types: IGNORED and parsing continues with the next entry
 *     (forward-compat with fields we may add later).
 *   - Duplicates: last wins (not an error to parse them).
 */

typedef struct {
    char origin   [META_ORIGIN_MAX + 1];   /* +1 for the '\0' */
    char to_name  [META_NAME_MAX + 1];
    char to_symbol[META_SYMBOL_MAX + 1];

    u8   to_decimals;

    u8   has_origin;
    u8   has_to_name;
    u8   has_to_symbol;
    u8   has_to_decimals;
} tx_meta;

/* Initialises every field to 0/'\0' and every flag to 0. ALWAYS call
 * before tx_meta_parse() — the parser only SETS the present fields,
 * it does not clear them. */
void tx_meta_init(tx_meta* m);

/* Parse a TLV blob. Returns 1 if everything is OK; 0 if some TLV is
 * truncated (len > remaining bytes). Unknown types are skipped without
 * failing. Out-of-range decimals are discarded (has_to_decimals stays 0). */
int tx_meta_parse(const u8* blob, u32 blob_len, tx_meta* out);

#endif
