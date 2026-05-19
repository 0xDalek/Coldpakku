/*
 * EIP-712 (typed data) parser + verifier for Coldpakku.
 *
 * Decodes the TLV tree the host appends to PROTO_TYPED_DATA (see
 * docs/PROTOCOL.md), rebuilds EIP712Domain + the primary message, and
 * recomputes domainSeparator + messageHash on-device. The caller
 * (handle_typed_data in state.c) then compares them against the values
 * the host sent and decides whether to enter "parsed view" or show the
 * "HOST HASH MISMATCH" screen.
 *
 * Scope and caps: see src/crypto/eip712.h. Pure C99, no libgba dep;
 * built natively on the host too (tests/host_test.py).
 */

#include "eip712.h"
#include "keccak256.h"

#include <string.h>

/* ============================================================================
 * Small helpers
 * ============================================================================ */

static u32 read_u32_be(const u8* p) {
    return ((u32)p[0] << 24) | ((u32)p[1] << 16) | ((u32)p[2] << 8) | (u32)p[3];
}

static int bytes_eq(const u8* a, u32 a_len, const u8* b, u32 b_len) {
    if (a_len != b_len) return 0;
    return memcmp(a, b, a_len) == 0;
}

/* Returns 1 if `s[0..len]` ends with ']' (any array kind). */
static int type_is_array(const u8* s, u32 len) {
    return len > 0 && s[len - 1] == ']';
}

/* Returns 1 if `s[0..len]` starts with `prefix`. */
static int starts_with(const u8* s, u32 len, const char* prefix) {
    u32 plen = (u32)strlen(prefix);
    if (len < plen) return 0;
    return memcmp(s, prefix, plen) == 0;
}

/* Parse a base-10 unsigned integer at `s[0..len]`. Returns -1 if the
 * string is empty or contains anything other than digits. Caps the
 * result at 0xFFFFFFFF; the caller is expected to validate the width. */
static s32 parse_decimal(const u8* s, u32 len) {
    if (len == 0) return -1;
    u32 n = 0;
    for (u32 i = 0; i < len; i++) {
        u8 c = s[i];
        if (c < '0' || c > '9') return -1;
        n = n * 10 + (u32)(c - '0');
    }
    return (s32)n;
}

/* For `uintN` / `intN` types: returns the bit width (8..256, multiple
 * of 8). Accepts empty suffix as 256. Returns -1 on malformed. */
static s32 parse_uint_width(const u8* s, u32 len) {
    s32 bits = (len == 0) ? 256 : parse_decimal(s, len);
    if (bits < 8 || bits > 256 || (bits & 7) != 0) return -1;
    return bits;
}

/* Find a type by name (linear scan — N <= 32). Returns -1 if absent. */
static s32 find_type_by_name(const eip712_tree_t* t, const u8* name, u32 name_len) {
    if (name_len == 0 || name_len > EIP712_MAX_NAME_LEN) return -1;
    for (u8 i = 0; i < t->num_types; i++) {
        if (t->types[i].name_len == name_len &&
            memcmp(t->tlv_base + t->types[i].name_off, name, name_len) == 0) {
            return i;
        }
    }
    return -1;
}

/* ============================================================================
 * TLV header parse: builds the type table + locates the values blobs.
 *
 * Layout (see docs/PROTOCOL.md):
 *   1B num_types
 *   repeat num_types: 1B name_len + name + 1B num_fields
 *                     + repeat num_fields: 1B fname_len + fname
 *                                        + 1B ftype_len + ftype
 *   1B primary_type_index
 *   <domain_values>
 *   <message_values>
 *
 * Returns the offset where domain_values start on success, or -1 on
 * malformed input.
 * ============================================================================ */

static s32 parse_tlv_header(eip712_tree_t* t) {
    const u8* tlv = t->tlv_base;
    u32 len = t->tlv_len;
    if (len < 2) return -1;

    u32 off = 0;
    u32 num_types = tlv[off++];
    if (num_types == 0 || num_types > EIP712_MAX_TYPES) return -1;
    t->num_types = (u8)num_types;

    for (u32 i = 0; i < num_types; i++) {
        eip712_type_t* ty = &t->types[i];

        if (off >= len) return -1;
        u32 nlen = tlv[off++];
        if (nlen == 0 || nlen > EIP712_MAX_NAME_LEN || off + nlen > len) return -1;
        ty->name_off = (u16)off;
        ty->name_len = (u8)nlen;
        off += nlen;

        if (off >= len) return -1;
        u32 nfields = tlv[off++];
        if (nfields == 0 || nfields > EIP712_MAX_FIELDS_PER_TYPE) return -1;
        ty->num_fields = (u8)nfields;

        for (u32 j = 0; j < nfields; j++) {
            eip712_field_t* f = &ty->fields[j];

            if (off >= len) return -1;
            u32 fname_len = tlv[off++];
            if (fname_len == 0 || fname_len > EIP712_MAX_NAME_LEN || off + fname_len > len)
                return -1;
            f->name_off = (u16)off;
            f->name_len = (u8)fname_len;
            off += fname_len;

            if (off >= len) return -1;
            u32 ftype_len = tlv[off++];
            if (ftype_len == 0 || ftype_len > EIP712_MAX_TYPE_LEN || off + ftype_len > len)
                return -1;
            f->type_off = (u16)off;
            f->type_len = (u8)ftype_len;
            off += ftype_len;
        }
    }

    if (off >= len) return -1;
    u32 primary = tlv[off++];
    if (primary >= num_types) return -1;
    t->primary_type_index = (u8)primary;

    /* Convention: index 0 must be EIP712Domain (the host writes it as the
     * first entry in the type table, see serializeTypedDataTLV). */
    if (t->types[0].name_len != 12 ||
        memcmp(tlv + t->types[0].name_off, "EIP712Domain", 12) != 0) {
        return -1;
    }
    return (s32)off;
}

/* ============================================================================
 * Value walking. Used to (a) compute span lengths for the domain and
 * message blobs, and (b) drive hash_struct's encodeValue loop. The
 * walker returns 0 on OK, -EIP712_ERR_MALFORMED / -EIP712_ERR_UNSUPPORTED
 * etc. as negative codes.
 * ============================================================================ */

/* Forward decls — three of the four are mutually recursive. */
static s32 walk_value(const eip712_tree_t* t, const u8* type_str, u32 type_len,
                      u32* cursor, u8 depth, int collect_hash, keccak256_ctx* hctx);
static s32 walk_struct(const eip712_tree_t* t, u8 type_idx,
                       u32* cursor, u8 depth, int collect_hash, keccak256_ctx* hctx);
static s32 compute_struct_hash(const eip712_tree_t* t, u8 type_idx,
                               u32 values_off, u32 values_len, u8 out[32]);

/* `walk_value` either skips the value (collect_hash=0) or hashes it
 * into hctx as the 32-byte word EIP-712 mandates (collect_hash=1).
 *
 * `cursor` is the offset inside t->tlv_base of the current read head; it
 * is advanced by the size of the value (raw bytes for atomics, 4B+N
 * for string/bytes, recursive span for structs).
 */
static s32 walk_value(const eip712_tree_t* t, const u8* type_str, u32 type_len,
                      u32* cursor, u8 depth, int collect_hash, keccak256_ctx* hctx) {
    if (depth > EIP712_MAX_DEPTH) return -EIP712_ERR_UNSUPPORTED;

    const u8* tlv = t->tlv_base;
    u32 tlv_len = t->tlv_len;

    /* Arrays: skipped only (UNSUPPORTED for hashing in v0.2). We still
     * consume the wire bytes so the rest of the values blob stays
     * parseable, but the top-level entry point will refuse to compare
     * hashes once any array is encountered. */
    if (type_is_array(type_str, type_len)) {
        if (collect_hash) return -EIP712_ERR_UNSUPPORTED;
        /* count + items */
        if (*cursor + 4 > tlv_len) return -EIP712_ERR_MALFORMED;
        u32 count = read_u32_be(tlv + *cursor);
        *cursor += 4;
        /* inner type = strip last "[...]" */
        u32 bracket = type_len;
        while (bracket > 0 && type_str[bracket - 1] != '[') bracket--;
        if (bracket == 0) return -EIP712_ERR_MALFORMED;
        u32 inner_len = bracket - 1;
        for (u32 i = 0; i < count; i++) {
            s32 rc = walk_value(t, type_str, inner_len, cursor, depth + 1, 0, NULL);
            if (rc < 0) return rc;
        }
        return 0;
    }

    /* Struct */
    s32 struct_idx = find_type_by_name(t, type_str, type_len);
    if (struct_idx >= 0) {
        if (collect_hash) {
            /* The 32B word for a nested struct is its hashStruct value.
             * We need to know its byte span first (so compute_struct_hash
             * can be called over a known [off..off+span] slice), so we
             * skip the struct twice: once to measure, then we hash. The
             * skip-and-measure walk is cheap (no keccak). */
            u32 start = *cursor;
            s32 rc = walk_struct(t, (u8)struct_idx, cursor, depth + 1, 0, NULL);
            if (rc < 0) return rc;
            u32 end = *cursor;
            u8 child_hash[32];
            rc = compute_struct_hash(t, (u8)struct_idx, start, end - start, child_hash);
            if (rc < 0) return rc;
            keccak256_update(hctx, child_hash, 32);
            return 0;
        }
        return walk_struct(t, (u8)struct_idx, cursor, depth + 1, 0, NULL);
    }

    /* string / dynamic bytes: 32B word = keccak256(raw bytes) */
    int is_string = (type_len == 6 && memcmp(type_str, "string", 6) == 0);
    int is_bytes  = (type_len == 5 && memcmp(type_str, "bytes",  5) == 0);
    if (is_string || is_bytes) {
        if (*cursor + 4 > tlv_len) return -EIP712_ERR_MALFORMED;
        u32 slen = read_u32_be(tlv + *cursor);
        *cursor += 4;
        if (slen > EIP712_MAX_STRING_LEN) return -EIP712_ERR_TOO_BIG;
        if (*cursor + slen > tlv_len) return -EIP712_ERR_MALFORMED;
        if (collect_hash) {
            u8 word[32];
            keccak256(tlv + *cursor, slen, word);
            keccak256_update(hctx, word, 32);
        }
        *cursor += slen;
        return 0;
    }

    /* address: 20 raw bytes, zero-padded left to 32 */
    if (type_len == 7 && memcmp(type_str, "address", 7) == 0) {
        if (*cursor + 20 > tlv_len) return -EIP712_ERR_MALFORMED;
        if (collect_hash) {
            u8 word[32];
            memset(word, 0, 12);
            memcpy(word + 12, tlv + *cursor, 20);
            keccak256_update(hctx, word, 32);
        }
        *cursor += 20;
        return 0;
    }

    /* bool: 1 byte (0/1), zero-padded left */
    if (type_len == 4 && memcmp(type_str, "bool", 4) == 0) {
        if (*cursor + 1 > tlv_len) return -EIP712_ERR_MALFORMED;
        u8 v = tlv[*cursor];
        if (v != 0 && v != 1) return -EIP712_ERR_MALFORMED;
        if (collect_hash) {
            u8 word[32];
            memset(word, 0, 32);
            word[31] = v;
            keccak256_update(hctx, word, 32);
        }
        *cursor += 1;
        return 0;
    }

    /* uintN / intN: N/8 raw big-endian bytes, zero-padded left to 32 */
    if (starts_with(type_str, type_len, "uint") || starts_with(type_str, type_len, "int")) {
        u32 prefix = starts_with(type_str, type_len, "uint") ? 4 : 3;
        s32 bits = parse_uint_width(type_str + prefix, type_len - prefix);
        if (bits < 0) return -EIP712_ERR_MALFORMED;
        u32 nbytes = (u32)bits / 8;
        if (*cursor + nbytes > tlv_len) return -EIP712_ERR_MALFORMED;
        if (collect_hash) {
            u8 word[32];
            /* For uint the high bytes are 0. For int we sign-extend. */
            u8 fill = 0;
            if (prefix == 3) {  /* signed */
                u8 top = tlv[*cursor];
                if (top & 0x80) fill = 0xFF;
            }
            memset(word, fill, 32 - nbytes);
            memcpy(word + (32 - nbytes), tlv + *cursor, nbytes);
            keccak256_update(hctx, word, 32);
        }
        *cursor += nbytes;
        return 0;
    }

    /* bytesN (N=1..32): N raw bytes, right-zero-padded to 32 */
    if (starts_with(type_str, type_len, "bytes")) {
        s32 nbytes = parse_decimal(type_str + 5, type_len - 5);
        if (nbytes < 1 || nbytes > 32) return -EIP712_ERR_MALFORMED;
        if (*cursor + (u32)nbytes > tlv_len) return -EIP712_ERR_MALFORMED;
        if (collect_hash) {
            u8 word[32];
            memcpy(word, tlv + *cursor, (u32)nbytes);
            if ((u32)nbytes < 32) memset(word + nbytes, 0, 32 - (u32)nbytes);
            keccak256_update(hctx, word, 32);
        }
        *cursor += (u32)nbytes;
        return 0;
    }

    /* Unknown / not supported type string. */
    return -EIP712_ERR_UNSUPPORTED;
}

static s32 walk_struct(const eip712_tree_t* t, u8 type_idx,
                       u32* cursor, u8 depth, int collect_hash, keccak256_ctx* hctx) {
    if (type_idx >= t->num_types) return -EIP712_ERR_MALFORMED;
    if (depth > EIP712_MAX_DEPTH) return -EIP712_ERR_UNSUPPORTED;
    const eip712_type_t* ty = &t->types[type_idx];
    for (u32 i = 0; i < ty->num_fields; i++) {
        const eip712_field_t* f = &ty->fields[i];
        s32 rc = walk_value(t, t->tlv_base + f->type_off, f->type_len,
                            cursor, depth, collect_hash, hctx);
        if (rc < 0) return rc;
    }
    return 0;
}

/* ============================================================================
 * encodeType: canonical type string per EIP-712 §5.1.
 *
 * Format = primary "(" field0.type " " field0.name "," ... ")"
 *        + concat( deps "(" ... ")" ), deps sorted alphabetically.
 *
 * We collect every struct type reachable from `primary` (excluding
 * primary itself), sort by name, then emit. Output is written into
 * `out` capped at `out_cap`; returns the total written length, or -1
 * on overflow / malformed.
 * ============================================================================ */

static int put_str(u8* out, u32 cap, u32* off, const u8* s, u32 n) {
    if (*off + n > cap) return -1;
    memcpy(out + *off, s, n);
    *off += n;
    return 0;
}

static int put_char(u8* out, u32 cap, u32* off, u8 c) {
    return put_str(out, cap, off, &c, 1);
}

/* DFS collect: for each struct type reachable from `from_idx` (including
 * itself), add it to deps[]. Skips primitive / atomic / array types
 * (those are not in t->types and have no encodeType representation). */
static s32 collect_deps(const eip712_tree_t* t, u8 from_idx,
                        u8 deps_out[EIP712_MAX_TYPES], u8 seen[EIP712_MAX_TYPES],
                        u8* count) {
    if (seen[from_idx]) return 0;
    seen[from_idx] = 1;
    if (*count >= EIP712_MAX_TYPES) return -EIP712_ERR_TOO_BIG;
    deps_out[(*count)++] = from_idx;
    const eip712_type_t* ty = &t->types[from_idx];
    for (u32 i = 0; i < ty->num_fields; i++) {
        const eip712_field_t* f = &ty->fields[i];
        const u8* tstr = t->tlv_base + f->type_off;
        u32 tlen = f->type_len;
        /* Strip array brackets (T[] still depends on T). */
        if (type_is_array(tstr, tlen)) {
            u32 bracket = tlen;
            while (bracket > 0 && tstr[bracket - 1] != '[') bracket--;
            if (bracket == 0) return -EIP712_ERR_MALFORMED;
            tlen = bracket - 1;
        }
        s32 child = find_type_by_name(t, tstr, tlen);
        if (child >= 0) {
            s32 rc = collect_deps(t, (u8)child, deps_out, seen, count);
            if (rc < 0) return rc;
        }
    }
    return 0;
}

/* Selection sort by type name (lexicographic on raw bytes); N <= 32. */
static void sort_deps_by_name(const eip712_tree_t* t, u8* deps, u8 count) {
    for (u8 i = 0; i < count; i++) {
        u8 best = i;
        const u8* bn = t->tlv_base + t->types[deps[best]].name_off;
        u8 bl = t->types[deps[best]].name_len;
        for (u8 j = i + 1; j < count; j++) {
            const u8* cn = t->tlv_base + t->types[deps[j]].name_off;
            u8 cl = t->types[deps[j]].name_len;
            u32 m = bl < cl ? bl : cl;
            int cmp = memcmp(cn, bn, m);
            if (cmp == 0) cmp = (int)cl - (int)bl;
            if (cmp < 0) {
                best = j;
                bn = cn;
                bl = cl;
            }
        }
        if (best != i) {
            u8 tmp = deps[i];
            deps[i] = deps[best];
            deps[best] = tmp;
        }
    }
}

/* Emit one type definition: "T(t0 n0,t1 n1,...)" into out. */
static s32 emit_struct_def(const eip712_tree_t* t, u8 type_idx,
                           u8* out, u32 cap, u32* off) {
    const eip712_type_t* ty = &t->types[type_idx];
    if (put_str(out, cap, off, t->tlv_base + ty->name_off, ty->name_len) < 0)
        return -EIP712_ERR_TOO_BIG;
    if (put_char(out, cap, off, '(') < 0) return -EIP712_ERR_TOO_BIG;
    for (u32 i = 0; i < ty->num_fields; i++) {
        const eip712_field_t* f = &ty->fields[i];
        if (i > 0 && put_char(out, cap, off, ',') < 0) return -EIP712_ERR_TOO_BIG;
        if (put_str(out, cap, off, t->tlv_base + f->type_off, f->type_len) < 0)
            return -EIP712_ERR_TOO_BIG;
        if (put_char(out, cap, off, ' ') < 0) return -EIP712_ERR_TOO_BIG;
        if (put_str(out, cap, off, t->tlv_base + f->name_off, f->name_len) < 0)
            return -EIP712_ERR_TOO_BIG;
    }
    if (put_char(out, cap, off, ')') < 0) return -EIP712_ERR_TOO_BIG;
    return 0;
}

/* Build encodeType(primary) into `out`; returns length written or <0. */
static s32 encode_type_canonical(const eip712_tree_t* t, u8 primary_idx,
                                 u8* out, u32 cap) {
    u8 deps[EIP712_MAX_TYPES];
    u8 seen[EIP712_MAX_TYPES];
    memset(seen, 0, sizeof(seen));
    u8 count = 0;
    s32 rc = collect_deps(t, primary_idx, deps, seen, &count);
    if (rc < 0) return rc;

    /* Reorder so primary is first; the rest sorted alphabetically. */
    /* Remove primary from `deps` and sort the tail. */
    u8 tail[EIP712_MAX_TYPES];
    u8 tail_count = 0;
    for (u8 i = 0; i < count; i++) {
        if (deps[i] != primary_idx) tail[tail_count++] = deps[i];
    }
    sort_deps_by_name(t, tail, tail_count);

    u32 off = 0;
    rc = emit_struct_def(t, primary_idx, out, cap, &off);
    if (rc < 0) return rc;
    for (u8 i = 0; i < tail_count; i++) {
        rc = emit_struct_def(t, tail[i], out, cap, &off);
        if (rc < 0) return rc;
    }
    return (s32)off;
}

/* typeHash(primary) = keccak256(encodeType(primary, ...)). */
static s32 compute_type_hash(const eip712_tree_t* t, u8 type_idx, u8 out[32]) {
    static u8 buf[EIP712_TYPESTR_MAX];
    s32 n = encode_type_canonical(t, type_idx, buf, sizeof(buf));
    if (n < 0) return n;
    keccak256(buf, (u32)n, out);
    return 0;
}

/* compute hashStruct(type_idx, values[off..off+len]). */
static s32 compute_struct_hash(const eip712_tree_t* t, u8 type_idx,
                               u32 values_off, u32 values_len, u8 out[32]) {
    u8 type_hash[32];
    s32 rc = compute_type_hash(t, type_idx, type_hash);
    if (rc < 0) return rc;

    keccak256_ctx ctx;
    keccak256_init(&ctx);
    keccak256_update(&ctx, type_hash, 32);

    u32 cursor = values_off;
    u32 end    = values_off + values_len;
    const eip712_type_t* ty = &t->types[type_idx];
    for (u32 i = 0; i < ty->num_fields; i++) {
        const eip712_field_t* f = &ty->fields[i];
        rc = walk_value(t, t->tlv_base + f->type_off, f->type_len,
                        &cursor, 1, 1, &ctx);
        if (rc < 0) return rc;
    }
    if (cursor != end) return -EIP712_ERR_MALFORMED;
    keccak256_final(&ctx, out);
    return 0;
}

/* ============================================================================
 * Domain extractor — pulls name / version / chainId / verifyingContract
 * out of EIP712Domain values into the convenience fields. Best-effort:
 * unknown fields are simply skipped (they still get walked so the
 * cursor stays aligned).
 *
 * We do this in a second walk over the domain values because the type
 * table may have re-ordered fields (the EIP-712 spec allows any subset
 * of [name, version, chainId, verifyingContract, salt] in any order).
 * ============================================================================ */

static void extract_domain_fields(eip712_tree_t* t) {
    /* defaults: all absent */
    t->domain_name_off = 0;
    t->domain_name_len = 0;
    t->domain_version_off = 0;
    t->domain_version_len = 0;
    t->domain_chain_id = 0;
    t->has_chain_id = 0;
    memset(t->domain_verifying_contract, 0, 20);
    t->has_verifying_contract = 0;

    const eip712_type_t* d = &t->types[0];   /* EIP712Domain */
    u32 cursor = t->domain_values_off;
    const u8* tlv = t->tlv_base;

    for (u32 i = 0; i < d->num_fields; i++) {
        const eip712_field_t* f = &d->fields[i];
        const u8* fname = tlv + f->name_off;
        u8 fname_len = f->name_len;
        const u8* ftype = tlv + f->type_off;
        u8 ftype_len = f->type_len;

        /* Snapshot the cursor *before* we walk, then read the field's
         * raw bytes via the known type before letting walk_value advance
         * it (we want both: the raw value for extraction, AND a clean
         * advance for the next field). */
        u32 before = cursor;

        /* string fields (name, version) — store offset + length */
        if (ftype_len == 6 && memcmp(ftype, "string", 6) == 0) {
            if (cursor + 4 > t->tlv_len) return;
            u32 slen = read_u32_be(tlv + cursor);
            if (slen > EIP712_MAX_NAME_LEN) slen = EIP712_MAX_NAME_LEN;
            if (cursor + 4 + slen > t->tlv_len) return;
            if (bytes_eq(fname, fname_len, (const u8*)"name", 4)) {
                t->domain_name_off = (u16)(cursor + 4);
                t->domain_name_len = (u8)slen;
            } else if (bytes_eq(fname, fname_len, (const u8*)"version", 7)) {
                t->domain_version_off = (u16)(cursor + 4);
                t->domain_version_len = (u8)slen;
            }
        }
        /* uint256 chainId */
        else if (bytes_eq(fname, fname_len, (const u8*)"chainId", 7) &&
                 (ftype_len == 7 && memcmp(ftype, "uint256", 7) == 0)) {
            if (cursor + 32 > t->tlv_len) return;
            /* take the low 4 bytes; chain ids are well below 2^32 */
            t->domain_chain_id = read_u32_be(tlv + cursor + 28);
            t->has_chain_id = 1;
        }
        /* address verifyingContract */
        else if (bytes_eq(fname, fname_len, (const u8*)"verifyingContract", 17) &&
                 (ftype_len == 7 && memcmp(ftype, "address", 7) == 0)) {
            if (cursor + 20 > t->tlv_len) return;
            memcpy(t->domain_verifying_contract, tlv + cursor, 20);
            t->has_verifying_contract = 1;
        }
        /* Advance cursor over the field, regardless of whether we
         * extracted it (skip mode = no hashing). */
        s32 rc = walk_value(t, ftype, ftype_len, &cursor, 1, 0, NULL);
        if (rc < 0) return;
        (void)before;
    }
}

/* ============================================================================
 * Public API
 * ============================================================================ */

eip712_status_t eip712_parse_and_verify(const u8* tlv, u32 tlv_len,
                                        const u8 host_domain_sep[32],
                                        const u8 host_msg_hash[32],
                                        eip712_tree_t* tree) {
    if (tree == NULL || tlv == NULL || tlv_len == 0) return EIP712_ERR_MALFORMED;
    if (tlv_len > 0xFFFF) return EIP712_ERR_TOO_BIG;

    memset(tree, 0, sizeof(*tree));
    tree->tlv_base = tlv;
    tree->tlv_len = (u16)tlv_len;

    /* Step 1: type table + primary index. */
    s32 vals_off = parse_tlv_header(tree);
    if (vals_off < 0) return EIP712_ERR_MALFORMED;

    /* Step 2: locate the domain and message values spans by walking
     * over them. We do a skip-only walk (no hashing). */
    u32 cursor = (u32)vals_off;
    tree->domain_values_off = (u16)cursor;
    s32 rc = walk_struct(tree, 0, &cursor, 1, 0, NULL);
    if (rc < 0) {
        return rc == -EIP712_ERR_UNSUPPORTED ? EIP712_ERR_UNSUPPORTED
             : rc == -EIP712_ERR_TOO_BIG     ? EIP712_ERR_TOO_BIG
             : EIP712_ERR_MALFORMED;
    }
    tree->domain_values_len = (u16)(cursor - tree->domain_values_off);

    tree->message_values_off = (u16)cursor;
    rc = walk_struct(tree, tree->primary_type_index, &cursor, 1, 0, NULL);
    if (rc < 0) {
        return rc == -EIP712_ERR_UNSUPPORTED ? EIP712_ERR_UNSUPPORTED
             : rc == -EIP712_ERR_TOO_BIG     ? EIP712_ERR_TOO_BIG
             : EIP712_ERR_MALFORMED;
    }
    tree->message_values_len = (u16)(cursor - tree->message_values_off);

    /* Trailing bytes after message_values? Either the host is buggy or
     * the TLV is being padded — refuse to accept. */
    if (cursor != tlv_len) return EIP712_ERR_MALFORMED;

    /* Step 3: extract convenience domain fields. */
    extract_domain_fields(tree);

    /* Step 4: compute domain separator + message hash. */
    rc = compute_struct_hash(tree, 0,
                             tree->domain_values_off, tree->domain_values_len,
                             tree->our_domain_separator);
    if (rc < 0) {
        return rc == -EIP712_ERR_UNSUPPORTED ? EIP712_ERR_UNSUPPORTED
             : rc == -EIP712_ERR_TOO_BIG     ? EIP712_ERR_TOO_BIG
             : EIP712_ERR_MALFORMED;
    }
    rc = compute_struct_hash(tree, tree->primary_type_index,
                             tree->message_values_off, tree->message_values_len,
                             tree->our_message_hash);
    if (rc < 0) {
        return rc == -EIP712_ERR_UNSUPPORTED ? EIP712_ERR_UNSUPPORTED
             : rc == -EIP712_ERR_TOO_BIG     ? EIP712_ERR_TOO_BIG
             : EIP712_ERR_MALFORMED;
    }

    /* Step 5: compare to host's. */
    if (memcmp(tree->our_domain_separator, host_domain_sep, 32) != 0 ||
        memcmp(tree->our_message_hash,     host_msg_hash,    32) != 0) {
        return EIP712_OK_MISMATCH;
    }
    return EIP712_OK_MATCH;
}

/* ============================================================================
 * UI helper: walk the values blob of a struct, invoking `visitor` once
 * per field with a pointer to the raw encoded bytes. The visitor uses
 * the type string (via field metadata) to decide how to render.
 * ============================================================================ */

int eip712_visit_struct(const eip712_tree_t* t, u8 type_idx,
                        u16 values_off, u16 values_len,
                        u8 depth,
                        eip712_field_visitor visitor, void* user) {
    if (type_idx >= t->num_types) return -1;
    if (depth > EIP712_MAX_DEPTH)  return -1;
    const eip712_type_t* ty = &t->types[type_idx];
    u32 cursor = values_off;
    u32 end    = (u32)values_off + (u32)values_len;
    const u8* tlv = t->tlv_base;

    for (u8 i = 0; i < ty->num_fields; i++) {
        const eip712_field_t* f = &ty->fields[i];
        const u8* tstr = tlv + f->type_off;
        u8 tlen = f->type_len;
        u32 start = cursor;
        u8 is_struct = 0;
        u8 is_array  = 0;

        if (type_is_array(tstr, tlen)) {
            is_array = 1;
        } else {
            s32 sidx = find_type_by_name(t, tstr, tlen);
            if (sidx >= 0) is_struct = 1;
        }

        /* Skip-walk to find the field's span. */
        s32 rc = walk_value(t, tstr, tlen, &cursor, depth, 0, NULL);
        if (rc < 0) return -1;
        if (cursor > end) return -1;

        int vrc = visitor(user, t, type_idx, i,
                          tlv + start, cursor - start,
                          is_struct, is_array, depth);
        if (vrc != 0) return vrc;
    }
    if (cursor != end) return -1;
    return 0;
}
