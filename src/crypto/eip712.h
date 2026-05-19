#ifndef CRYPTO_EIP712_H
#define CRYPTO_EIP712_H

#include "../types.h"

/*
 * On-device EIP-712 (typed data) parser and verifier.
 *
 * The host always sends `PROTO_TYPED_DATA` (see src/link/protocol.h) with
 * pre-computed `domainSeparator` and `messageHash`. When `tree_len > 0`
 * the host appends a TLV tree of the typed data; the user can request a
 * "parsed view" on the confirm screen, at which point this module
 * decodes the tree, recomputes the two hashes on-device, and reports
 * whether they match the host's.
 *
 * Scope (v0.2, "Ledger-without-plugin" subset):
 *   - atomic types: address, bool, uintN/intN (N = 8..256, mult. of 8),
 *     bytesN (N = 1..32)
 *   - dynamic types: string, bytes
 *   - nested structs up to EIP712_MAX_DEPTH
 *   - arrays (T[], T[N]) -> flagged as UNSUPPORTED; on detection the
 *     verifier returns EIP712_ERR_UNSUPPORTED and the cartridge falls
 *     back to blind sign (A on the confirm screen) with a clear warning.
 *
 * Memory: the type table holds OFFSETS into the original TLV buffer
 * (kept alive by the protocol layer for the duration of the confirm
 * loop), so the tree itself is ~6 KB and lives in EWRAM. The hashing
 * uses the incremental keccak API, so encodeData is never staged.
 */

/* Caps mirrored in src/link/protocol.h, docs/PROTOCOL.md and the
 * extension's lib/eip712.ts. Picked to cover the common Ledger-supported
 * subset comfortably:
 *   - Permit2 PermitSingle:  2 types,  6 fields total, depth 2
 *   - ERC-2612 Permit:       2 types,  9 fields total, depth 1
 *   - OpenSea Seaport order: 5 types, ~30 fields, depth 3 (arrays =
 *     UNSUPPORTED so it falls back to blind sign anyway)
 */
#define EIP712_MAX_TYPES               32u
#define EIP712_MAX_FIELDS_PER_TYPE     32u
#define EIP712_MAX_NAME_LEN            32u
#define EIP712_MAX_TYPE_LEN            40u
#define EIP712_MAX_STRING_LEN        1024u
#define EIP712_MAX_DEPTH                4u

/* Buffer the encoded type string is composed into while computing the
 * type hash. Worst case = 32 types * (32 name + ~32 fields * (32 type
 * + 32 name + 2 separators) + 2 parens + 1 comma) but in practice
 * never larger than ~512 B; 2 KB is a comfortable cap and stays small
 * enough to live on the EWRAM workspace next to the tree. */
#define EIP712_TYPESTR_MAX           2048u

typedef enum {
    EIP712_OK_MATCH = 0,         /* tree decoded, recomputed hashes == host's */
    EIP712_OK_MISMATCH = 1,      /* tree decoded, recomputed hashes != host's */
    EIP712_ERR_MALFORMED = 2,    /* TLV truncated, bad lengths, name overflow... */
    EIP712_ERR_UNSUPPORTED = 3,  /* arrays, salt/bytes32-only domain, depth > cap */
    EIP712_ERR_TOO_BIG = 4,      /* type count / field count / typestr over cap */
} eip712_status_t;

/* Single field of a struct. Holds offsets relative to `tlv_base` plus
 * the lengths needed to slice the name and the type string. 6 bytes. */
typedef struct {
    u16 name_off;
    u16 type_off;
    u8  name_len;
    u8  type_len;
} eip712_field_t;

/* Struct definition. ~196 bytes. */
typedef struct {
    u16 name_off;
    u8  name_len;
    u8  num_fields;
    eip712_field_t fields[EIP712_MAX_FIELDS_PER_TYPE];
} eip712_type_t;

/* Whole decoded tree. ~6.4 KB; lives in EWRAM. */
typedef struct {
    const u8* tlv_base;   /* the protocol-owned RX buffer; offsets are relative */
    u16 tlv_len;          /* tree_len from the wire */

    u8 num_types;
    u8 primary_type_index;
    eip712_type_t types[EIP712_MAX_TYPES];

    /* Slices into `tlv_base` where the two values blobs live. */
    u16 domain_values_off;
    u16 domain_values_len;
    u16 message_values_off;
    u16 message_values_len;

    /* Filled by eip712_parse_and_verify(): the hashes the cartridge
     * recomputed from the tree. If status == EIP712_OK_MATCH they are
     * equal to the host-supplied ones; otherwise the diff is shown on
     * the MISMATCH screen for the user to inspect manually. */
    u8 our_domain_separator[32];
    u8 our_message_hash[32];

    /* Convenience extract from EIP712Domain (filled best-effort while
     * decoding domain_values). Used by the chain-lock check and by the
     * parsed-view UI. Each *_len = 0 means the field was absent. */
    u16 domain_name_off;
    u8  domain_name_len;
    u16 domain_version_off;
    u8  domain_version_len;
    u32 domain_chain_id;
    u8  has_chain_id;
    u8  domain_verifying_contract[20];
    u8  has_verifying_contract;
} eip712_tree_t;

/* Decode the TLV tree at `tlv[0..tlv_len]`, recompute the EIP-712 hashes
 * and compare them to the host-supplied ones.
 *
 * On EIP712_OK_MATCH or EIP712_OK_MISMATCH the caller can read
 * `tree->*` to render the parsed view. The pointers in the tree alias
 * the input buffer, which the caller MUST keep alive while the parsed
 * view is shown.
 *
 * The function never aborts on bad input: it always returns one of the
 * `eip712_status_t` codes. Hashing uses the incremental keccak API, so
 * peak transient stack usage stays below ~600 B.
 */
eip712_status_t eip712_parse_and_verify(const u8* tlv, u32 tlv_len,
                                        const u8 host_domain_sep[32],
                                        const u8 host_msg_hash[32],
                                        eip712_tree_t* tree);

/* Helper for the UI: iterate field values. Given a struct type index and
 * the matching values slice, walk through each field and call `visitor`
 * with the field's metadata plus a pointer to its raw encoded value.
 * The visitor MUST return 0 to continue or non-zero to stop the walk;
 * the walk result is the visitor's return code or -1 on malformed data.
 *
 * For nested structs the visitor receives `is_struct=1` and the
 * raw_value pointer/length cover the whole sub-blob; recurse with
 * `eip712_visit_struct` again on `tree->types[<idx>]` to drill in. */
typedef int (*eip712_field_visitor)(void* user,
                                    const eip712_tree_t* tree,
                                    u8 type_idx, u8 field_idx,
                                    const u8* raw_value, u32 raw_value_len,
                                    u8 is_struct, u8 is_array,
                                    u8 depth);

int eip712_visit_struct(const eip712_tree_t* tree, u8 type_idx,
                        u16 values_off, u16 values_len,
                        u8 depth,
                        eip712_field_visitor visitor, void* user);

#endif
