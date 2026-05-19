"""
EIP-712 v7 algorithm oracle.

Re-implements the on-device parser + hasher (src/crypto/eip712.c) in
Python, then validates it against the canonical implementation in
`eth_account.messages.encode_typed_data` for several real-world typed
data payloads (ERC-2612 Permit, Permit2 PermitSingle, ...).

Why this exists: until we have native gcc available to build
tests/host_test.py's shared library, this is the closest we can get to
testing the on-device algorithm without flashing a GBA. The Python port
mirrors the C control flow line-by-line: parse_tlv_header, walk_value,
collect_deps + sort_deps_by_name, emit_struct_def, compute_struct_hash.
If a bug exists in eip712.c, it will (almost always) be visible here
too.

Usage:
    python3 tests/eip712_oracle.py

Exit code 0 if every vector matches eth_account, 1 otherwise.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "pc"))

from eth_account.messages import encode_typed_data
from eth_utils import keccak

from protocol import serialize_typed_data_tlv  # type: ignore


# ---------------------------------------------------------------------------
# Port of src/crypto/eip712.c — keep the function names and the logic
# aligned so a divergence here also exposes a C bug.
# ---------------------------------------------------------------------------

class ParseError(Exception):
    pass


def _read_u32_be(b: bytes, off: int) -> int:
    return int.from_bytes(b[off:off + 4], "big")


def _type_is_array(t: bytes) -> bool:
    return len(t) > 0 and t[-1:] == b"]"


def _parse_uint_width(s: bytes) -> int:
    if not s:
        return 256
    n = 0
    for c in s:
        if c < 0x30 or c > 0x39:
            raise ParseError(f"bad width {s!r}")
        n = n * 10 + (c - 0x30)
    if n < 8 or n > 256 or n % 8 != 0:
        raise ParseError(f"width out of range {n}")
    return n


def parse_tlv_header(tlv: bytes):
    """Returns (types, primary_idx, values_offset).

    types is a list of dicts: {"name": bytes, "fields": [{"name", "type"}]}
    """
    off = 0
    if len(tlv) < 2:
        raise ParseError("tlv too short")
    num_types = tlv[off]; off += 1
    if num_types == 0 or num_types > 32:
        raise ParseError(f"bad num_types {num_types}")
    types = []
    for _ in range(num_types):
        nlen = tlv[off]; off += 1
        if nlen == 0 or nlen > 32:
            raise ParseError("bad name_len")
        name = tlv[off:off + nlen]; off += nlen
        nf = tlv[off]; off += 1
        if nf == 0 or nf > 32:
            raise ParseError("bad num_fields")
        fields = []
        for _ in range(nf):
            fnl = tlv[off]; off += 1
            if fnl == 0 or fnl > 32:
                raise ParseError("bad fname_len")
            fn = tlv[off:off + fnl]; off += fnl
            ftl = tlv[off]; off += 1
            if ftl == 0 or ftl > 40:
                raise ParseError("bad ftype_len")
            ft = tlv[off:off + ftl]; off += ftl
            fields.append({"name": fn, "type": ft})
        types.append({"name": name, "fields": fields})

    primary = tlv[off]; off += 1
    if primary >= num_types:
        raise ParseError("bad primary index")

    if types[0]["name"] != b"EIP712Domain":
        raise ParseError("types[0] must be EIP712Domain")
    return types, primary, off


def find_struct_idx(types, name: bytes) -> int:
    for i, t in enumerate(types):
        if t["name"] == name:
            return i
    return -1


def walk_value(types, tlv: bytes, tstr: bytes, cursor: int, depth: int,
               collect_hash: bool, parts: list) -> int:
    """Mirror of walk_value() in eip712.c.

    Either skips the value (collect_hash=False) or appends the 32-byte
    EIP-712 word to `parts` (collect_hash=True). Returns the new cursor.
    """
    if depth > 4:
        raise ParseError("depth > EIP712_MAX_DEPTH")

    if _type_is_array(tstr):
        # v0.2: hashing arrays is UNSUPPORTED, skip-only allowed
        if collect_hash:
            raise ParseError("UNSUPPORTED array in hashing path")
        count = _read_u32_be(tlv, cursor); cursor += 4
        bracket = tstr.rfind(b"[")
        if bracket < 0:
            raise ParseError("bad array type")
        inner = tstr[:bracket]
        for _ in range(count):
            cursor = walk_value(types, tlv, inner, cursor, depth + 1, False, parts)
        return cursor

    struct_idx = find_struct_idx(types, tstr)
    if struct_idx >= 0:
        if collect_hash:
            # Hash the child struct, append its hashStruct as a 32B word.
            start = cursor
            cursor = walk_struct(types, tlv, struct_idx, cursor, depth + 1, False, [])
            end = cursor
            child_hash = compute_struct_hash(types, tlv, struct_idx, start, end - start)
            parts.append(child_hash)
            return cursor
        return walk_struct(types, tlv, struct_idx, cursor, depth + 1, False, [])

    if tstr == b"string" or tstr == b"bytes":
        slen = _read_u32_be(tlv, cursor); cursor += 4
        if collect_hash:
            parts.append(keccak(tlv[cursor:cursor + slen]))
        return cursor + slen

    if tstr == b"address":
        if collect_hash:
            parts.append(b"\x00" * 12 + tlv[cursor:cursor + 20])
        return cursor + 20

    if tstr == b"bool":
        v = tlv[cursor]
        if collect_hash:
            parts.append(b"\x00" * 31 + bytes([v]))
        return cursor + 1

    if tstr.startswith(b"uint") or tstr.startswith(b"int"):
        prefix = 4 if tstr.startswith(b"uint") else 3
        bits = _parse_uint_width(tstr[prefix:])
        n = bits // 8
        raw = tlv[cursor:cursor + n]
        if collect_hash:
            fill = b"\x00" * (32 - n)
            if prefix == 3 and raw and (raw[0] & 0x80):
                fill = b"\xff" * (32 - n)
            parts.append(fill + raw)
        return cursor + n

    if tstr.startswith(b"bytes"):
        n = int(tstr[5:])
        if n < 1 or n > 32:
            raise ParseError("bad bytesN")
        raw = tlv[cursor:cursor + n]
        if collect_hash:
            parts.append(raw + b"\x00" * (32 - n))
        return cursor + n

    raise ParseError(f"unknown type {tstr!r}")


def walk_struct(types, tlv: bytes, type_idx: int, cursor: int, depth: int,
                collect_hash: bool, parts: list) -> int:
    for f in types[type_idx]["fields"]:
        cursor = walk_value(types, tlv, f["type"], cursor, depth, collect_hash, parts)
    return cursor


def collect_deps(types, from_idx: int, seen: set) -> list:
    """DFS-collect every struct type reachable from `from_idx`, returning
    the indices in discovery order (including `from_idx` itself)."""
    if from_idx in seen:
        return []
    seen.add(from_idx)
    out = [from_idx]
    for f in types[from_idx]["fields"]:
        t = f["type"]
        if _type_is_array(t):
            bracket = t.rfind(b"[")
            t = t[:bracket]
        child = find_struct_idx(types, t)
        if child >= 0:
            out += collect_deps(types, child, seen)
    return out


def encode_type_canonical(types, primary_idx: int) -> bytes:
    deps = collect_deps(types, primary_idx, set())
    tail = sorted([d for d in deps if d != primary_idx],
                  key=lambda i: types[i]["name"])
    ordered = [primary_idx] + tail
    parts = []
    for idx in ordered:
        ty = types[idx]
        s = ty["name"] + b"("
        s += b",".join(f["type"] + b" " + f["name"] for f in ty["fields"])
        s += b")"
        parts.append(s)
    return b"".join(parts)


def compute_struct_hash(types, tlv: bytes, type_idx: int,
                        values_off: int, values_len: int) -> bytes:
    type_hash = keccak(encode_type_canonical(types, type_idx))
    parts = [type_hash]
    cursor = walk_struct(types, tlv, type_idx, values_off, 1, True, parts)
    if cursor != values_off + values_len:
        raise ParseError("trailing bytes in struct values")
    return keccak(b"".join(parts))


def parse_and_verify_py(tlv: bytes):
    """Full mirror of eip712_parse_and_verify(). Returns
    (domain_separator, message_hash)."""
    types, primary, off = parse_tlv_header(tlv)

    domain_off = off
    cursor = walk_struct(types, tlv, 0, off, 1, False, [])
    domain_len = cursor - domain_off

    message_off = cursor
    cursor = walk_struct(types, tlv, primary, cursor, 1, False, [])
    message_len = cursor - message_off

    if cursor != len(tlv):
        raise ParseError(f"trailing bytes: {cursor} != {len(tlv)}")

    ds = compute_struct_hash(types, tlv, 0, domain_off, domain_len)
    mh = compute_struct_hash(types, tlv, primary, message_off, message_len)
    return ds, mh


# ---------------------------------------------------------------------------
# Vectors + runner
# ---------------------------------------------------------------------------

PERMIT_TD = {
    "types": {
        "EIP712Domain": [
            {"name": "name", "type": "string"},
            {"name": "version", "type": "string"},
            {"name": "chainId", "type": "uint256"},
            {"name": "verifyingContract", "type": "address"},
        ],
        "Permit": [
            {"name": "owner", "type": "address"},
            {"name": "spender", "type": "address"},
            {"name": "value", "type": "uint256"},
            {"name": "nonce", "type": "uint256"},
            {"name": "deadline", "type": "uint256"},
        ],
    },
    "primaryType": "Permit",
    "domain": {
        "name": "USD Coin",
        "version": "2",
        "chainId": 1,
        "verifyingContract": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
    },
    "message": {
        "owner": "0x1111111111111111111111111111111111111111",
        "spender": "0x2222222222222222222222222222222222222222",
        "value": 1000000,
        "nonce": 0,
        "deadline": 1735689600,
    },
}

PERMIT2_TD = {
    "types": {
        "EIP712Domain": [
            {"name": "name", "type": "string"},
            {"name": "chainId", "type": "uint256"},
            {"name": "verifyingContract", "type": "address"},
        ],
        "PermitDetails": [
            {"name": "token", "type": "address"},
            {"name": "amount", "type": "uint160"},
            {"name": "expiration", "type": "uint48"},
            {"name": "nonce", "type": "uint48"},
        ],
        "PermitSingle": [
            {"name": "details", "type": "PermitDetails"},
            {"name": "spender", "type": "address"},
            {"name": "sigDeadline", "type": "uint256"},
        ],
    },
    "primaryType": "PermitSingle",
    "domain": {
        "name": "Permit2",
        "chainId": 1,
        "verifyingContract": "0x000000000022D473030F116dDEE9F6B43aC78BA3",
    },
    "message": {
        "details": {
            "token": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
            "amount": 1000000000000,
            "expiration": 1735689600,
            "nonce": 0,
        },
        "spender": "0x3333333333333333333333333333333333333333",
        "sigDeadline": 1735776000,
    },
}

# A vector that exercises bytes32 and dynamic bytes fields.
MAIL_TD = {
    "types": {
        "EIP712Domain": [
            {"name": "name", "type": "string"},
            {"name": "version", "type": "string"},
            {"name": "chainId", "type": "uint256"},
            {"name": "verifyingContract", "type": "address"},
        ],
        "Person": [
            {"name": "name", "type": "string"},
            {"name": "wallet", "type": "address"},
        ],
        "Mail": [
            {"name": "from", "type": "Person"},
            {"name": "to", "type": "Person"},
            {"name": "contents", "type": "string"},
            {"name": "hash", "type": "bytes32"},
            {"name": "extra", "type": "bytes"},
        ],
    },
    "primaryType": "Mail",
    "domain": {
        "name": "Ether Mail",
        "version": "1",
        "chainId": 1,
        "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
    },
    "message": {
        "from": {"name": "Alice", "wallet": "0xa11ce00000000000000000000000000000000000"},
        "to":   {"name": "Bob",   "wallet": "0xb0b0000000000000000000000000000000000000"},
        "contents": "Hello, Bob!",
        "hash": "0x" + "ab" * 32,
        "extra": "0xdeadbeef",
    },
}


def run_vector(name: str, td: dict) -> bool:
    print(f"\n--- {name} ---")
    tlv = serialize_typed_data_tlv(td)
    sm = encode_typed_data(full_message=td)
    expect_ds, expect_mh = bytes(sm.header), bytes(sm.body)
    print(f"TLV: {len(tlv)} bytes")
    try:
        got_ds, got_mh = parse_and_verify_py(tlv)
    except Exception as e:
        print(f"  [FAIL] oracle threw {type(e).__name__}: {e}")
        return False
    ok = True
    if got_ds == expect_ds:
        print(f"  [OK]  domainSeparator = {got_ds.hex()}")
    else:
        print(f"  [FAIL] domainSeparator")
        print(f"          got:  {got_ds.hex()}")
        print(f"          want: {expect_ds.hex()}")
        ok = False
    if got_mh == expect_mh:
        print(f"  [OK]  messageHash    = {got_mh.hex()}")
    else:
        print(f"  [FAIL] messageHash")
        print(f"          got:  {got_mh.hex()}")
        print(f"          want: {expect_mh.hex()}")
        ok = False
    return ok


def main() -> int:
    failures = 0
    for name, td in [
        ("ERC-2612 Permit (USDC)",   PERMIT_TD),
        ("Permit2 PermitSingle",     PERMIT2_TD),
        ("Mail (string/bytes32/bytes/nested Person)", MAIL_TD),
    ]:
        if not run_vector(name, td):
            failures += 1
    print()
    if failures:
        print(f"=== {failures} vectors FAILED ===")
        return 1
    print("=== ALL vectors match eth_account ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
