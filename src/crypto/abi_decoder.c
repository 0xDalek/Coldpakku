#include "abi_decoder.h"

#include <string.h>

/* ----------------------------- helpers ----------------------------- */

/* Number of high padding bytes that MUST be 0x00 for a static type to
 * be considered well-formed. For uintN this is (32 - N/8). For
 * address it is 12. For bool it is 31 (and the low byte must be 0 or
 * 1, see validate_pad). For bytesN the padding is at the LOW end, not
 * the high end, so this helper does not apply — see validate_pad. */
static u8 high_pad_bytes_for(abi_type_t t) {
    switch (t) {
        case ABI_T_BOOL:    return 31;
        case ABI_T_UINT8:   return 31;
        case ABI_T_UINT16:  return 30;
        case ABI_T_UINT24:  return 29;
        case ABI_T_UINT32:  return 28;
        case ABI_T_UINT48:  return 26;
        case ABI_T_UINT64:  return 24;
        case ABI_T_UINT128: return 16;
        case ABI_T_UINT160: return 12;
        case ABI_T_ADDRESS: return 12;
        /* uint256 / int256 / bytes32 / deadline-as-uint256 have no
         * high-pad constraint (any pattern is valid). Returning 0 here
         * makes validate_pad a no-op. */
        default: return 0;
    }
}

static int validate_pad(abi_type_t type, const u8 slot[32]) {
    u8 hp = high_pad_bytes_for(type);
    for (u8 i = 0; i < hp; i++) {
        if (slot[i] != 0) return 0;
    }
    if (type == ABI_T_BOOL) {
        /* low byte must be strictly 0 or 1 */
        if (slot[31] != 0 && slot[31] != 1) return 0;
    }
    if (type == ABI_T_BYTES4) {
        /* low 28 bytes (positions 4..31) must be 0 — bytesN is LEFT
         * aligned in the slot, padding is on the right. */
        for (u8 i = 4; i < 32; i++) {
            if (slot[i] != 0) return 0;
        }
    }
    /* bytes32: any pattern */
    /* uint256/int256/deadline: any pattern */
    return 1;
}

/* True if the type is a dynamic ABI type (its head slot is an offset
 * to a (length, payload) tail). */
static int is_dynamic(abi_type_t t) {
    switch (t) {
        case ABI_T_BYTES:
        case ABI_T_STRING:
        case ABI_T_ADDRESS_ARRAY:
        case ABI_T_BYTES_SUB_COUNT:
        case ABI_T_BYTES_ARRAY_SUB_COUNT:
            return 1;
        default:
            return 0;
    }
}

/* Reads a 32-byte ABI slot as a u32. The high 28 bytes MUST be 0,
 * otherwise it does not fit in a u32 (which means the calldata is
 * either malformed or far larger than anything we can render on a
 * 30-column screen — either way we refuse). */
static int read_slot_as_u32(const u8 slot[32], u32* out) {
    for (u8 i = 0; i < 28; i++) {
        if (slot[i] != 0) return 0;
    }
    *out = ((u32)slot[28] << 24) | ((u32)slot[29] << 16)
         | ((u32)slot[30] << 8)  | (u32)slot[31];
    return 1;
}

/* ----------------------------- main entry ----------------------------- */

abi_dec_status_t abi_decode(const u8* data, u32 data_len, abi_decoded_t* out) {
    if (!out) return ABI_DEC_ERR_TRUNCATED;
    out->fn = 0;
    out->num_args = 0;

    if (!data || data_len < 4) return ABI_DEC_ERR_NO_SELECTOR;

    const abi_known_fn_t* fn = abi_lookup_selector(data);
    if (!fn) return ABI_DEC_ERR_UNKNOWN_SEL;

    if (fn->num_args > ABI_DECODED_MAX_ARGS) return ABI_DEC_ERR_TOO_MANY_ARGS;

    const u8* args_base = data + 4;
    u32       args_len  = data_len - 4;

    /* Zero-args (e.g. deposit()) is OK: we just leave out->args
     * untouched and report success. */
    out->fn = fn;
    out->num_args = fn->num_args;
    if (fn->num_args == 0) return ABI_DEC_OK;

    u32 head_pos = 0;
    for (u8 i = 0; i < fn->num_args; i++) {
        abi_type_t type = fn->args[i].type;
        out->args[i].type = type;

        if (head_pos + 32 > args_len) return ABI_DEC_ERR_TRUNCATED;

        const u8* head_slot = args_base + head_pos;

        if (!is_dynamic(type)) {
            /* Static: head IS the value. Validate padding and copy. */
            memcpy(out->args[i].v.raw, head_slot, 32);
            if (!validate_pad(type, head_slot)) return ABI_DEC_ERR_BAD_PAD;
            head_pos += 32;
            continue;
        }

        /* Dynamic: head is an offset (relative to args_base) into the
         * tail region. The tail starts with a 32 B length prefix. */
        u32 offset;
        if (!read_slot_as_u32(head_slot, &offset)) return ABI_DEC_ERR_BAD_OFFSET;
        /* Offsets are required to be 32-byte aligned by the Solidity
         * ABI; an off-alignment is a strong sign of malformed calldata. */
        if (offset & 0x1F) return ABI_DEC_ERR_BAD_OFFSET;
        if (offset + 32 > args_len) return ABI_DEC_ERR_TRUNCATED;

        u32 length;
        if (!read_slot_as_u32(args_base + offset, &length)) return ABI_DEC_ERR_BAD_OFFSET;

        const u8* payload = args_base + offset + 32;

        switch (type) {
            case ABI_T_BYTES:
            case ABI_T_STRING:
            case ABI_T_BYTES_SUB_COUNT: {
                /* `length` is the byte count. The actual storage is
                 * padded up to a multiple of 32, but we only need
                 * length bytes for rendering. */
                if (offset + 32 + length > args_len) return ABI_DEC_ERR_TRUNCATED;
                out->args[i].v.dyn.count = length;
                out->args[i].v.dyn.ptr   = payload;
                break;
            }
            case ABI_T_ADDRESS_ARRAY: {
                /* `length` is the element count; each element is a
                 * full 32-byte ABI slot (address with 12 B left pad).
                 * Sanity-cap the count to avoid pathological calldata
                 * tripping the multiply; address[] in real swap paths
                 * is at most ~5 hops, MAX 64 keeps headroom. */
                if (length > 64) return ABI_DEC_ERR_UNSUP_TYPE;
                u32 payload_len = length * 32u;
                if (offset + 32 + payload_len > args_len) return ABI_DEC_ERR_TRUNCATED;
                /* We validate each address's 12 B high pad lazily in
                 * the formatter (lets us still render the count even
                 * if one element is dirty, which the user can spot). */
                out->args[i].v.dyn.count = length;
                out->args[i].v.dyn.ptr   = payload;
                break;
            }
            case ABI_T_BYTES_ARRAY_SUB_COUNT: {
                /* bytes[] tail layout: 32 B count, then `count` 32 B
                 * head offsets, each pointing to its own (length, raw)
                 * inner tail. We only need `count` for the UI hint, so
                 * we do NOT walk the inner tails. We do verify the
                 * head offsets array fits in the args buffer so we
                 * don't promise a count that's impossibly large. */
                if (length > 64) return ABI_DEC_ERR_UNSUP_TYPE;
                u32 head_arr_len = length * 32u;
                if (offset + 32 + head_arr_len > args_len) return ABI_DEC_ERR_TRUNCATED;
                out->args[i].v.dyn.count = length;
                out->args[i].v.dyn.ptr   = payload;
                break;
            }
            default:
                return ABI_DEC_ERR_UNSUP_TYPE;
        }

        head_pos += 32;
    }

    return ABI_DEC_OK;
}
