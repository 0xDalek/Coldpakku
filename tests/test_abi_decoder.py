"""Tests for the generic ABI calldata decoder (src/crypto/abi_decoder.c).

Compile abi_decoder.c + abi_selectors.c with native gcc and expose via
ctypes. For each test vector we:
  1. Build canonical ABI calldata with eth_abi (Python lib) as the
     oracle (so the test setup itself is independent of our C code).
  2. Decode it with our C decoder.
  3. Assert that the decoded values match what eth_abi produced and the
     human-readable names from abi_selectors.c are exposed.

Usage: python3 tests/test_abi_decoder.py
"""
from __future__ import annotations

import ctypes
import subprocess
import sys
import tempfile
from pathlib import Path

try:
    from eth_abi import encode as abi_encode
except ImportError:
    print("ERROR: pip install eth_abi")
    sys.exit(2)

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"

# Mirror the enum in abi_selectors.h. If the order changes there, this
# table must change too — the test will catch that.
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

MAX_ARGS = 8


class _Dyn(ctypes.Structure):
    _fields_ = [
        ("count", ctypes.c_uint32),
        ("ptr", ctypes.c_void_p),
    ]


class _Val(ctypes.Union):
    _fields_ = [
        ("raw", ctypes.c_uint8 * 32),
        ("dyn", _Dyn),
    ]


class _Arg(ctypes.Structure):
    _fields_ = [
        ("type", ctypes.c_int),
        ("v", _Val),
    ]


class _Decoded(ctypes.Structure):
    _fields_ = [
        ("fn", ctypes.c_void_p),
        ("num_args", ctypes.c_uint32),
        ("args", _Arg * MAX_ARGS),
    ]


class _KnownFn(ctypes.Structure):
    _fields_ = [
        ("selector_be", ctypes.c_uint32),
        ("func_name", ctypes.c_char_p),
        ("args", ctypes.c_void_p),
        ("num_args", ctypes.c_uint8),
        ("flags", ctypes.c_uint8),
    ]


def _have_gcc() -> bool:
    try:
        subprocess.run(["gcc", "--version"], capture_output=True, check=True)
        return True
    except (FileNotFoundError, subprocess.CalledProcessError):
        return False


def build_lib() -> ctypes.CDLL:
    out = Path(tempfile.gettempdir()) / "libgbasigner_abi_decoder.so"
    cmd = [
        "gcc", "-O2", "-fPIC", "-shared", "-Wall", "-Wextra",
        "-include", str(SRC / "shim_host.h"),
        "-I", str(SRC),
        "-I", str(SRC / "crypto"),
        str(SRC / "crypto" / "abi_decoder.c"),
        str(SRC / "crypto" / "abi_selectors.c"),
        "-o", str(out),
    ]
    subprocess.run(cmd, check=True)
    lib = ctypes.CDLL(str(out))
    lib.abi_decode.argtypes = [
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.c_uint32,
        ctypes.POINTER(_Decoded),
    ]
    lib.abi_decode.restype = ctypes.c_int
    lib.abi_lookup_selector.argtypes = [ctypes.POINTER(ctypes.c_uint8)]
    lib.abi_lookup_selector.restype = ctypes.POINTER(_KnownFn)
    return lib


def decode(lib, data: bytes):
    out = _Decoded()
    buf = (ctypes.c_uint8 * len(data))(*data) if data else (ctypes.c_uint8 * 0)()
    rc = lib.abi_decode(buf, len(data), ctypes.byref(out))
    return rc, out


def selector(sig: str) -> bytes:
    from eth_utils import keccak
    return keccak(text=sig)[:4]


def encode_call(sig: str, abi_types: list[str], values: list) -> bytes:
    inner_types = sig[sig.index("(") + 1 : sig.rindex(")")].split(",")
    inner_types = [t.strip() for t in inner_types if t.strip()]
    assert inner_types == abi_types, (inner_types, abi_types)
    return selector(sig) + abi_encode(abi_types, values)


_TYPE_NAMES = {
    v: k for k, v in globals().items() if k.startswith("T_") or k.startswith("DEC_")
}


def check(name: str, cond: bool, extra: str = "") -> int:
    if cond:
        print(f"[OK]  {name}")
        return 0
    print(f"[FAIL] {name}  {extra}")
    return 1


def fn_name(lib, sel: bytes) -> str | None:
    sel_buf = (ctypes.c_uint8 * 4)(*sel)
    p = lib.abi_lookup_selector(sel_buf)
    if not p:
        return None
    fn = p.contents
    return fn.func_name.decode()


def main() -> int:
    if not _have_gcc():
        print("SKIP test_abi_decoder.py: native gcc not available "
              "(install build-essential or run on a host with gcc).")
        print("Use tests/abi_decoder_oracle.py for a gcc-independent check.")
        return 0
    print("compiling abi_decoder + abi_selectors as shared lib...")
    lib = build_lib()

    failures = 0
    TO = "0xAaBbCcDdEeFf00112233445566778899aAbBcCdD"
    FROM = "0x1111111111111111111111111111111111111111"
    SPENDER = "0x2222222222222222222222222222222222222222"
    OWNER = "0x3333333333333333333333333333333333333333"

    MAX_U256 = (1 << 256) - 1

    # ---- ERC-20 transfer ----
    data = encode_call("transfer(address,uint256)",
                       ["address", "uint256"], [TO, 1500000])
    rc, d = decode(lib, data)
    failures += check("transfer: rc=OK", rc == DEC_OK, f"rc={rc}")
    failures += check("transfer: fn=transfer", fn_name(lib, data[:4]) == "transfer")
    failures += check("transfer: num_args=2", d.num_args == 2)
    failures += check("transfer: arg0 is ADDRESS", d.args[0].type == T_ADDRESS)
    addr = bytes(d.args[0].v.raw)[12:].hex()
    failures += check("transfer: to matches", addr == TO[2:].lower())
    val = int.from_bytes(bytes(d.args[1].v.raw), "big")
    failures += check("transfer: amount=1500000", val == 1500000)

    # ---- ERC-20 approve (normal) ----
    data = encode_call("approve(address,uint256)",
                       ["address", "uint256"], [SPENDER, 42])
    rc, d = decode(lib, data)
    failures += check("approve: rc=OK", rc == DEC_OK)
    val = int.from_bytes(bytes(d.args[1].v.raw), "big")
    failures += check("approve: amount=42", val == 42)

    # ---- ERC-20 approve INFINITE ----
    data = encode_call("approve(address,uint256)",
                       ["address", "uint256"], [SPENDER, MAX_U256])
    rc, d = decode(lib, data)
    failures += check("approve(MAX): rc=OK", rc == DEC_OK)
    failures += check("approve(MAX): all-FF",
                      all(b == 0xff for b in bytes(d.args[1].v.raw)))

    # ---- ERC-20 transferFrom ----
    data = encode_call("transferFrom(address,address,uint256)",
                       ["address", "address", "uint256"], [FROM, TO, 999])
    rc, d = decode(lib, data)
    failures += check("transferFrom: rc=OK", rc == DEC_OK)
    failures += check("transferFrom: num_args=3", d.num_args == 3)
    failures += check("transferFrom: from", bytes(d.args[0].v.raw)[12:].hex()
                      == FROM[2:].lower())
    failures += check("transferFrom: to", bytes(d.args[1].v.raw)[12:].hex()
                      == TO[2:].lower())
    failures += check("transferFrom: amount=999",
                      int.from_bytes(bytes(d.args[2].v.raw), "big") == 999)

    # ---- WETH deposit() (no args) ----
    data = bytes.fromhex("d0e30db0")
    rc, d = decode(lib, data)
    failures += check("deposit: rc=OK", rc == DEC_OK)
    failures += check("deposit: num_args=0", d.num_args == 0)
    failures += check("deposit: fn=deposit", fn_name(lib, data[:4]) == "deposit")

    # ---- WETH withdraw(uint256) ----
    data = encode_call("withdraw(uint256)", ["uint256"], [10**18])
    rc, d = decode(lib, data)
    failures += check("withdraw: rc=OK", rc == DEC_OK)
    failures += check("withdraw: amount=1e18",
                      int.from_bytes(bytes(d.args[0].v.raw), "big") == 10**18)

    # ---- setApprovalForAll(operator, true) ----
    data = encode_call("setApprovalForAll(address,bool)",
                       ["address", "bool"], [SPENDER, True])
    rc, d = decode(lib, data)
    failures += check("setAppForAll(true): rc=OK", rc == DEC_OK)
    failures += check("setAppForAll(true): bool=1", d.args[1].v.raw[31] == 1)

    # ---- setApprovalForAll(operator, false) ----
    data = encode_call("setApprovalForAll(address,bool)",
                       ["address", "bool"], [SPENDER, False])
    rc, d = decode(lib, data)
    failures += check("setAppForAll(false): rc=OK", rc == DEC_OK)
    failures += check("setAppForAll(false): bool=0", d.args[1].v.raw[31] == 0)

    # ---- ERC-2612 permit(...) ----
    deadline = 1_800_000_000
    data = encode_call(
        "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
        ["address", "address", "uint256", "uint256", "uint8", "bytes32", "bytes32"],
        [OWNER, SPENDER, 10**6, deadline, 27,
         b"\x11" * 32, b"\x22" * 32])
    rc, d = decode(lib, data)
    failures += check("permit: rc=OK", rc == DEC_OK)
    failures += check("permit: num_args=7", d.num_args == 7)
    failures += check("permit: deadline preserved",
                      int.from_bytes(bytes(d.args[3].v.raw), "big") == deadline)
    failures += check("permit: v=27", d.args[4].v.raw[31] == 27)
    failures += check("permit: r preserved",
                      bytes(d.args[5].v.raw) == b"\x11" * 32)

    # ---- swapExactTokensForTokens(amountIn,amountOutMin,path[],to,deadline) ----
    PATH = [SPENDER, OWNER, TO]
    data = encode_call(
        "swapExactTokensForTokens(uint256,uint256,address[],address,uint256)",
        ["uint256", "uint256", "address[]", "address", "uint256"],
        [10**18, 10**17, PATH, OWNER, deadline])
    rc, d = decode(lib, data)
    failures += check("swap V2: rc=OK", rc == DEC_OK, f"rc={rc}")
    failures += check("swap V2: num_args=5", d.num_args == 5)
    failures += check("swap V2: amountIn=1e18",
                      int.from_bytes(bytes(d.args[0].v.raw), "big") == 10**18)
    failures += check("swap V2: arg2 ADDRESS_ARRAY",
                      d.args[2].type == T_ADDRESS_ARRAY)
    failures += check("swap V2: path count=3", d.args[2].v.dyn.count == 3)
    # Read the 3 addresses from dyn.ptr (32 bytes each, address at low 20).
    addrs = []
    for i in range(3):
        addr_slot = ctypes.string_at(d.args[2].v.dyn.ptr + i * 32, 32)
        addrs.append("0x" + addr_slot[12:].hex())
    failures += check("swap V2: path elements", addrs == [a.lower() for a in PATH],
                      f"got {addrs}")
    failures += check("swap V2: to preserved",
                      bytes(d.args[3].v.raw)[12:].hex() == OWNER[2:].lower())

    # ---- Universal Router execute(commands,inputs,deadline) ----
    cmds = bytes.fromhex("0a0b0c")     # 3 sub-commands
    inputs = [b"\x01" * 32, b"\x02" * 64, b"\x03" * 96]
    data = encode_call("execute(bytes,bytes[],uint256)",
                       ["bytes", "bytes[]", "uint256"],
                       [cmds, inputs, deadline])
    rc, d = decode(lib, data)
    failures += check("UR execute: rc=OK", rc == DEC_OK, f"rc={rc}")
    failures += check("UR execute: fn=execute",
                      fn_name(lib, data[:4]) == "execute")
    failures += check("UR execute: cmds count=3",
                      d.args[0].v.dyn.count == 3,
                      f"got {d.args[0].v.dyn.count}")
    failures += check("UR execute: inputs count=3",
                      d.args[1].v.dyn.count == 3)
    failures += check("UR execute: deadline preserved",
                      int.from_bytes(bytes(d.args[2].v.raw), "big") == deadline)

    # ---- multicall(bytes[]) ----
    calls = [b"\xaa" * 20, b"\xbb" * 40, b"\xcc" * 60, b"\xdd" * 80]
    data = encode_call("multicall(bytes[])", ["bytes[]"], [calls])
    rc, d = decode(lib, data)
    failures += check("multicall: rc=OK", rc == DEC_OK, f"rc={rc}")
    failures += check("multicall: count=4", d.args[0].v.dyn.count == 4)

    # ============ MALFORMED ============

    # Unknown selector
    rc, _ = decode(lib, bytes.fromhex("deadbeef") + b"\x00" * 32)
    failures += check("reject unknown selector", rc == DEC_ERR_UNKNOWN_SEL,
                      f"rc={rc}")

    # Truncated calldata (approve missing the value slot)
    data = bytes.fromhex("095ea7b3") + b"\x00" * 32
    rc, _ = decode(lib, data)
    failures += check("reject truncated approve", rc == DEC_ERR_TRUNCATED)

    # Bad address padding (byte 11 != 0)
    dirty_addr = b"\x00" * 11 + b"\x01" + bytes.fromhex(TO[2:])
    data = bytes.fromhex("095ea7b3") + dirty_addr + b"\x00" * 32
    rc, _ = decode(lib, data)
    failures += check("reject dirty address pad", rc == DEC_ERR_BAD_PAD)

    # Bad bool value (>= 2)
    data = encode_call("setApprovalForAll(address,bool)",
                       ["address", "bool"], [SPENDER, True])
    data = data[:-1] + b"\x02"  # tamper the last byte
    rc, _ = decode(lib, data)
    failures += check("reject bool=2", rc == DEC_ERR_BAD_PAD)

    # Empty / <4 bytes
    rc, _ = decode(lib, b"")
    failures += check("reject empty", rc == DEC_ERR_NO_SELECTOR)
    rc, _ = decode(lib, b"\xa9\x05\x9c")
    failures += check("reject <4 bytes", rc == DEC_ERR_NO_SELECTOR)

    # Unaligned dynamic offset (not multiple of 32).
    data = encode_call("multicall(bytes[])", ["bytes[]"], [[b"\xaa"]])
    # The first 32 bytes after the selector are the offset (= 0x20).
    # Tamper to make it 0x21 (unaligned).
    data = data[:4] + (0x21).to_bytes(32, "big") + data[36:]
    rc, _ = decode(lib, data)
    failures += check("reject unaligned offset", rc == DEC_ERR_BAD_OFFSET)

    print()
    if failures:
        print(f"=== {failures} failures ===")
        return 1
    print("=== ALL OK ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
