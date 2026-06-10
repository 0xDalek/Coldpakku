"""Python re-implementation of src/crypto/abi_decoder.c.

This oracle exists so the firmware's ABI calldata decoder has an
executable spec that does NOT depend on the ARM toolchain (so it runs
in CI / in the assistant's sandbox where no native gcc is installed),
and so we can cross-check our hand-rolled walker against the canonical
`eth_abi` Python library.

The set of supported types and the validation rules mirror exactly
those of abi_decoder.c. If a type rule changes there, also change it
here and vice-versa — `test_abi_decoder.py` (the C-side test) will
catch any drift on hosts that DO have gcc.

Usage: python3 tests/abi_decoder_oracle.py
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

try:
    from eth_abi import encode as abi_encode
    from eth_abi import decode as abi_decode_canonical
    from eth_utils import keccak
except ImportError:
    raise SystemExit("pip install eth_abi eth_utils")


# ---------------------------------------------------------------------------
# Hardcoded mirror of abi_selectors.c. If you add an entry there, mirror it
# here as well. The order of args matters (display order).
# ---------------------------------------------------------------------------

T_END = 0
T_ADDRESS = 1
T_BOOL = 2
T_UINT8 = 3
T_UINT16 = 4
T_UINT24 = 5
T_UINT32 = 6
T_UINT48 = 7
T_UINT64 = 8
T_UINT128 = 9
T_UINT160 = 10
T_UINT256 = 11
T_INT256 = 12
T_BYTES4 = 13
T_BYTES32 = 14
T_BYTES = 15
T_STRING = 16
T_ADDRESS_ARRAY = 17
T_BYTES_SUB_COUNT = 18
T_BYTES_ARRAY_SUB_COUNT = 19
T_DEADLINE_UINT256 = 20

# Status codes from abi_dec_status_t.
DEC_OK = 0
DEC_ERR_NO_SELECTOR = 1
DEC_ERR_UNKNOWN_SEL = 2
DEC_ERR_TRUNCATED = 3
DEC_ERR_BAD_PAD = 4
DEC_ERR_BAD_OFFSET = 5
DEC_ERR_TOO_MANY_ARGS = 6
DEC_ERR_UNSUP_TYPE = 7

# Mapping from our internal type to the canonical ABI type string. Used
# both to compute selectors (where the canonical signature lives) and as
# a fallback path to `eth_abi` for cross-checks.
ABI_TYPE_STR = {
    T_ADDRESS: "address",
    T_BOOL: "bool",
    T_UINT8: "uint8",
    T_UINT16: "uint16",
    T_UINT24: "uint24",
    T_UINT32: "uint32",
    T_UINT48: "uint48",
    T_UINT64: "uint64",
    T_UINT128: "uint128",
    T_UINT160: "uint160",
    T_UINT256: "uint256",
    T_INT256: "int256",
    T_BYTES4: "bytes4",
    T_BYTES32: "bytes32",
    T_BYTES: "bytes",
    T_STRING: "string",
    T_ADDRESS_ARRAY: "address[]",
    T_BYTES_SUB_COUNT: "bytes",        # wire-equivalent to plain bytes
    T_BYTES_ARRAY_SUB_COUNT: "bytes[]",
    T_DEADLINE_UINT256: "uint256",
}


@dataclass
class Arg:
    name: str
    type: int


@dataclass
class KnownFn:
    selector_be: int   # the 4-byte selector as a u32 BE
    func_name: str
    args: list[Arg]

    @property
    def num_args(self) -> int:
        return len(self.args)

    @property
    def canonical_sig(self) -> str:
        inner = ",".join(ABI_TYPE_STR[a.type] for a in self.args)
        # Many entries' func_name is the abbreviated label (`execute`
        # vs `executeNoDeadln`); the canonical SIGNATURE for the
        # selector lives separately. For sigs that the abbreviated
        # label doesn't disambiguate we look up the real signature
        # in CANONICAL_SIGS below.
        return f"{self.func_name}({inner})"


# Canonical signatures we use to compute selectors. The key is the
# selector_be int; the value is the exact string that goes through
# keccak256 to produce that selector. This map is what makes the
# oracle independent of the func_name labels used in abi_selectors.c.
CANONICAL_SIGS = {
    0xa9059cbb: "transfer(address,uint256)",
    0x095ea7b3: "approve(address,uint256)",
    0x23b872dd: "transferFrom(address,address,uint256)",
    0x40c10f19: "mint(address,uint256)",
    0x42966c68: "burn(uint256)",
    0x42842e0e: "safeTransferFrom(address,address,uint256)",
    0xb88d4fde: "safeTransferFrom(address,address,uint256,bytes)",
    0xa22cb465: "setApprovalForAll(address,bool)",
    0xd0e30db0: "deposit()",
    0x2e1a7d4d: "withdraw(uint256)",
    0xd505accf: "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
    0x7ff36ab5: "swapExactETHForTokens(uint256,address[],address,uint256)",
    0x18cbafe5: "swapExactTokensForETH(uint256,uint256,address[],address,uint256)",
    0x38ed1739: "swapExactTokensForTokens(uint256,uint256,address[],address,uint256)",
    0x4a25d94a: "swapTokensForExactETH(uint256,uint256,address[],address,uint256)",
    0xfb3bdb41: "swapETHForExactTokens(uint256,address[],address,uint256)",
    0x8803dbee: "swapTokensForExactTokens(uint256,uint256,address[],address,uint256)",
    0xf305d719: "addLiquidityETH(address,uint256,uint256,uint256,address,uint256)",
    0xe8e33700: "addLiquidity(address,address,uint256,uint256,uint256,uint256,address,uint256)",
    0xbaa2abde: "removeLiquidity(address,address,uint256,uint256,uint256,address,uint256)",
    0x02751cec: "removeLiquidityETH(address,uint256,uint256,uint256,address,uint256)",
    0xac9650d8: "multicall(bytes[])",
    0x5ae401dc: "multicall(uint256,bytes[])",
    0x3593564c: "execute(bytes,bytes[],uint256)",
    0x24856bc3: "execute(bytes,bytes[])",
}


def _args(*pairs: tuple[str, int]) -> list[Arg]:
    return [Arg(n, t) for n, t in pairs]


KNOWN_FUNCS: list[KnownFn] = [
    KnownFn(0xa9059cbb, "transfer",     _args(("to", T_ADDRESS), ("amount", T_UINT256))),
    KnownFn(0x095ea7b3, "approve",      _args(("spender", T_ADDRESS), ("amount", T_UINT256))),
    KnownFn(0x23b872dd, "transferFrom", _args(("from", T_ADDRESS), ("to", T_ADDRESS), ("amount", T_UINT256))),
    KnownFn(0x40c10f19, "mint",         _args(("to", T_ADDRESS), ("amount", T_UINT256))),
    KnownFn(0x42966c68, "burn",         _args(("amount", T_UINT256))),
    KnownFn(0x42842e0e, "safeTransferFrom",
            _args(("from", T_ADDRESS), ("to", T_ADDRESS), ("tokenId", T_UINT256))),
    KnownFn(0xb88d4fde, "safeTransferFromData",
            _args(("from", T_ADDRESS), ("to", T_ADDRESS), ("tokenId", T_UINT256), ("data", T_BYTES))),
    KnownFn(0xa22cb465, "setApprovalForAll",
            _args(("operator", T_ADDRESS), ("approved", T_BOOL))),
    KnownFn(0xd0e30db0, "deposit",  []),
    KnownFn(0x2e1a7d4d, "withdraw", _args(("amount", T_UINT256))),
    KnownFn(0xd505accf, "permit",
            _args(("owner", T_ADDRESS), ("spender", T_ADDRESS),
                  ("value", T_UINT256), ("deadline", T_DEADLINE_UINT256),
                  ("v", T_UINT8), ("r", T_BYTES32), ("s", T_BYTES32))),
    KnownFn(0x7ff36ab5, "swapExactETHForTokens",
            _args(("amountOutMin", T_UINT256), ("path", T_ADDRESS_ARRAY),
                  ("to", T_ADDRESS), ("deadline", T_DEADLINE_UINT256))),
    KnownFn(0x18cbafe5, "swapExactTokensForETH",
            _args(("amountIn", T_UINT256), ("amountOutMin", T_UINT256),
                  ("path", T_ADDRESS_ARRAY), ("to", T_ADDRESS),
                  ("deadline", T_DEADLINE_UINT256))),
    KnownFn(0x38ed1739, "swapExactTokensForTokens",
            _args(("amountIn", T_UINT256), ("amountOutMin", T_UINT256),
                  ("path", T_ADDRESS_ARRAY), ("to", T_ADDRESS),
                  ("deadline", T_DEADLINE_UINT256))),
    KnownFn(0x4a25d94a, "swapTokensForExactETH",
            _args(("amountOut", T_UINT256), ("amountInMax", T_UINT256),
                  ("path", T_ADDRESS_ARRAY), ("to", T_ADDRESS),
                  ("deadline", T_DEADLINE_UINT256))),
    KnownFn(0xfb3bdb41, "swapETHForExactTokens",
            _args(("amountOut", T_UINT256), ("path", T_ADDRESS_ARRAY),
                  ("to", T_ADDRESS), ("deadline", T_DEADLINE_UINT256))),
    KnownFn(0x8803dbee, "swapTokensForExactTokens",
            _args(("amountOut", T_UINT256), ("amountInMax", T_UINT256),
                  ("path", T_ADDRESS_ARRAY), ("to", T_ADDRESS),
                  ("deadline", T_DEADLINE_UINT256))),
    KnownFn(0xac9650d8, "multicall",
            _args(("calls", T_BYTES_ARRAY_SUB_COUNT))),
    KnownFn(0x5ae401dc, "multicallDeadln",
            _args(("deadline", T_DEADLINE_UINT256),
                  ("calls", T_BYTES_ARRAY_SUB_COUNT))),
    KnownFn(0x3593564c, "execute",
            _args(("commands", T_BYTES_SUB_COUNT),
                  ("inputs", T_BYTES_ARRAY_SUB_COUNT),
                  ("deadline", T_DEADLINE_UINT256))),
    KnownFn(0x24856bc3, "executeNoDeadln",
            _args(("commands", T_BYTES_SUB_COUNT),
                  ("inputs", T_BYTES_ARRAY_SUB_COUNT))),
]


def lookup(selector: bytes) -> Optional[KnownFn]:
    sel_int = int.from_bytes(selector, "big")
    for fn in KNOWN_FUNCS:
        if fn.selector_be == sel_int:
            return fn
    return None


# ---------------------------------------------------------------------------
# Oracle decoder (mirrors abi_decoder.c)
# ---------------------------------------------------------------------------

_DYNAMIC = {T_BYTES, T_STRING, T_ADDRESS_ARRAY,
            T_BYTES_SUB_COUNT, T_BYTES_ARRAY_SUB_COUNT}

# (type) -> number of high padding bytes that must be 0x00.
_HIGH_PAD = {
    T_BOOL: 31, T_UINT8: 31, T_UINT16: 30, T_UINT24: 29, T_UINT32: 28,
    T_UINT48: 26, T_UINT64: 24, T_UINT128: 16, T_UINT160: 12,
    T_ADDRESS: 12,
}


def _validate_pad(type_: int, slot: bytes) -> bool:
    hp = _HIGH_PAD.get(type_, 0)
    if any(b != 0 for b in slot[:hp]):
        return False
    if type_ == T_BOOL and slot[31] not in (0, 1):
        return False
    if type_ == T_BYTES4 and any(b != 0 for b in slot[4:]):
        return False
    return True


def _slot_as_u32(slot: bytes) -> Optional[int]:
    if any(b != 0 for b in slot[:28]):
        return None
    return int.from_bytes(slot[28:32], "big")


@dataclass
class DecodedArg:
    type: int
    raw: Optional[bytes] = None         # for static types: the 32 B slot
    dyn_count: Optional[int] = None     # for dynamic types
    dyn_payload: Optional[bytes] = None # bytes of the payload (post-length)


@dataclass
class Decoded:
    fn: KnownFn
    args: list[DecodedArg]


def decode(data: bytes) -> tuple[int, Optional[Decoded]]:
    if len(data) < 4:
        return DEC_ERR_NO_SELECTOR, None
    fn = lookup(data[:4])
    if fn is None:
        return DEC_ERR_UNKNOWN_SEL, None
    if fn.num_args > 8:
        return DEC_ERR_TOO_MANY_ARGS, None

    if fn.num_args == 0:
        return DEC_OK, Decoded(fn=fn, args=[])

    args_base = data[4:]
    args_len = len(args_base)
    decoded = []

    head_pos = 0
    for arg in fn.args:
        if head_pos + 32 > args_len:
            return DEC_ERR_TRUNCATED, None
        head_slot = args_base[head_pos:head_pos + 32]
        if arg.type not in _DYNAMIC:
            if not _validate_pad(arg.type, head_slot):
                return DEC_ERR_BAD_PAD, None
            decoded.append(DecodedArg(type=arg.type, raw=head_slot))
            head_pos += 32
            continue

        offset = _slot_as_u32(head_slot)
        if offset is None:
            return DEC_ERR_BAD_OFFSET, None
        if offset & 0x1F:
            return DEC_ERR_BAD_OFFSET, None
        if offset + 32 > args_len:
            return DEC_ERR_TRUNCATED, None

        length = _slot_as_u32(args_base[offset:offset + 32])
        if length is None:
            return DEC_ERR_BAD_OFFSET, None

        if arg.type in (T_BYTES, T_STRING, T_BYTES_SUB_COUNT):
            if offset + 32 + length > args_len:
                return DEC_ERR_TRUNCATED, None
            payload = args_base[offset + 32:offset + 32 + length]
            decoded.append(DecodedArg(type=arg.type, dyn_count=length,
                                      dyn_payload=payload))
        elif arg.type == T_ADDRESS_ARRAY:
            if length > 64:
                return DEC_ERR_UNSUP_TYPE, None
            need = length * 32
            if offset + 32 + need > args_len:
                return DEC_ERR_TRUNCATED, None
            payload = args_base[offset + 32:offset + 32 + need]
            decoded.append(DecodedArg(type=arg.type, dyn_count=length,
                                      dyn_payload=payload))
        elif arg.type == T_BYTES_ARRAY_SUB_COUNT:
            if length > 64:
                return DEC_ERR_UNSUP_TYPE, None
            need = length * 32
            if offset + 32 + need > args_len:
                return DEC_ERR_TRUNCATED, None
            payload = args_base[offset + 32:offset + 32 + need]
            decoded.append(DecodedArg(type=arg.type, dyn_count=length,
                                      dyn_payload=payload))
        else:
            return DEC_ERR_UNSUP_TYPE, None

        head_pos += 32

    return DEC_OK, Decoded(fn=fn, args=decoded)


# ---------------------------------------------------------------------------
# Self-tests + cross-check vs eth_abi
# ---------------------------------------------------------------------------

def _encode_canonical(selector_be: int, abi_types: list[str], values: list) -> bytes:
    sig = CANONICAL_SIGS[selector_be]
    inner = sig[sig.index("(") + 1:sig.rindex(")")]
    inner_types = [t.strip() for t in inner.split(",") if t.strip()]
    assert inner_types == abi_types, (inner_types, abi_types)
    selector = keccak(text=sig)[:4]
    return selector + abi_encode(abi_types, values)


def _check(label: str, cond: bool, extra: str = "") -> int:
    if cond:
        print(f"[OK]  {label}")
        return 0
    print(f"[FAIL] {label}  {extra}")
    return 1


def main() -> int:
    failures = 0

    # 1. Validate the selectors stored in the table all match
    #    keccak256(canonical_sig) (catches typos in the table).
    for fn in KNOWN_FUNCS:
        sig = CANONICAL_SIGS[fn.selector_be]
        computed = int.from_bytes(keccak(text=sig)[:4], "big")
        failures += _check(
            f"selector match: {fn.func_name} <- {sig}",
            computed == fn.selector_be,
            f"computed=0x{computed:08x} table=0x{fn.selector_be:08x}",
        )

    TO = "0xAaBbCcDdEeFf00112233445566778899aAbBcCdD"
    SPENDER = "0x2222222222222222222222222222222222222222"
    OWNER = "0x3333333333333333333333333333333333333333"
    MAX_U256 = (1 << 256) - 1

    # 2. Decode happy-path vectors and cross-check vs eth_abi.
    cases = [
        ("transfer", 0xa9059cbb, ["address", "uint256"], [TO, 1500000]),
        ("approve normal", 0x095ea7b3, ["address", "uint256"], [SPENDER, 42]),
        ("approve MAX", 0x095ea7b3, ["address", "uint256"], [SPENDER, MAX_U256]),
        ("transferFrom", 0x23b872dd, ["address", "address", "uint256"],
            [OWNER, TO, 999]),
        ("withdraw", 0x2e1a7d4d, ["uint256"], [10**18]),
        ("setApprovalForAll(true)", 0xa22cb465, ["address", "bool"],
            [SPENDER, True]),
        ("permit", 0xd505accf,
            ["address", "address", "uint256", "uint256", "uint8", "bytes32", "bytes32"],
            [OWNER, SPENDER, 10**6, 1_800_000_000, 27,
             b"\x11" * 32, b"\x22" * 32]),
        ("swapExactTokensForTokens", 0x38ed1739,
            ["uint256", "uint256", "address[]", "address", "uint256"],
            [10**18, 10**17, [SPENDER, OWNER, TO], OWNER, 1_800_000_000]),
        ("UR execute", 0x3593564c,
            ["bytes", "bytes[]", "uint256"],
            [b"\x0a\x0b\x0c", [b"\x01" * 32, b"\x02" * 64], 1_800_000_000]),
        ("multicall", 0xac9650d8, ["bytes[]"],
            [[b"\xaa" * 20, b"\xbb" * 40, b"\xcc" * 60]]),
    ]
    for label, sel, abi_types, values in cases:
        calldata = _encode_canonical(sel, abi_types, values)
        rc, decoded = decode(calldata)
        if not _check(f"{label}: oracle decodes OK", rc == DEC_OK, f"rc={rc}"):
            # Also verify eth_abi can decode it (sanity on our encoder).
            canonical = abi_decode_canonical(abi_types, calldata[4:])
            for i, (a, c) in enumerate(zip(decoded.args, canonical)):
                if a.raw is not None:
                    abi_str = ABI_TYPE_STR[a.type]
                    re_decoded = abi_decode_canonical([abi_str], a.raw)[0]
                    failures += _check(
                        f"{label}: arg[{i}] {a.type} matches canonical",
                        re_decoded == c,
                        f"oracle={re_decoded!r} canonical={c!r}",
                    )
                else:
                    if a.type in (T_BYTES, T_STRING, T_BYTES_SUB_COUNT):
                        # Length-prefixed: payload is exactly the value.
                        failures += _check(
                            f"{label}: arg[{i}] bytes/string matches",
                            a.dyn_payload == (c if isinstance(c, bytes) else c.encode()),
                        )
                    elif a.type == T_ADDRESS_ARRAY:
                        addrs = ["0x" + a.dyn_payload[j * 32 + 12:(j + 1) * 32].hex()
                                 for j in range(a.dyn_count)]
                        failures += _check(
                            f"{label}: arg[{i}] address[] matches",
                            [x.lower() for x in addrs] == [x.lower() for x in c],
                        )
                    elif a.type == T_BYTES_ARRAY_SUB_COUNT:
                        failures += _check(
                            f"{label}: arg[{i}] bytes[] count matches",
                            a.dyn_count == len(c),
                        )

    # 3. Malformed: rejected with the right status.
    rc, _ = decode(b"")
    failures += _check("reject empty", rc == DEC_ERR_NO_SELECTOR)
    rc, _ = decode(b"\xde\xad\xbe\xef" + b"\x00" * 32)
    failures += _check("reject unknown selector", rc == DEC_ERR_UNKNOWN_SEL)
    rc, _ = decode(bytes.fromhex("095ea7b3") + b"\x00" * 32)
    failures += _check("reject truncated approve", rc == DEC_ERR_TRUNCATED)
    dirty = b"\x00" * 11 + b"\x01" + b"\x00" * 20
    rc, _ = decode(bytes.fromhex("095ea7b3") + dirty + b"\x00" * 32)
    failures += _check("reject dirty address pad", rc == DEC_ERR_BAD_PAD)
    bad_bool = b"\x00" * 31 + b"\x02"
    rc, _ = decode(bytes.fromhex("a22cb465") + b"\x00" * 12
                   + b"\xaa" * 20 + bad_bool)
    failures += _check("reject bool=2", rc == DEC_ERR_BAD_PAD)
    # Unaligned dyn offset
    cd = _encode_canonical(0xac9650d8, ["bytes[]"], [[b"\xaa"]])
    cd = cd[:4] + (0x21).to_bytes(32, "big") + cd[36:]
    rc, _ = decode(cd)
    failures += _check("reject unaligned offset", rc == DEC_ERR_BAD_OFFSET)

    print()
    if failures:
        print(f"=== {failures} failures ===")
        return 1
    print("=== ALL OK ===")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
