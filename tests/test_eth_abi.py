"""Tests for the ABI selector decoder (src/crypto/eth_abi.c).

Compile eth_abi.c with native gcc and expose it via ctypes. Vectors:
- transfer / approve / transferFrom / safeTransferFrom / setApprovalForAll
- approve(max_uint256) -> is_infinite
- malformed: length, non-zero padding, bool outside {0,1}, unknown selector

Usage: python3 tests/test_eth_abi.py
"""
from __future__ import annotations

import ctypes
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"

UNKNOWN = 0
TRANSFER = 1
APPROVE = 2
TRANSFER_FROM = 3
SAFE_TRANSFER_FROM = 4
SET_APPROVAL_FOR_ALL = 5


class EthAbiCall(ctypes.Structure):
    _fields_ = [
        ("kind", ctypes.c_uint8),
        ("addr_a", ctypes.c_uint8 * 20),
        ("addr_b", ctypes.c_uint8 * 20),
        ("has_addr_b", ctypes.c_uint8),
        ("value_be", ctypes.c_uint8 * 32),
        ("is_infinite", ctypes.c_uint8),
        ("approved_bool", ctypes.c_uint8),
    ]


def build_lib() -> ctypes.CDLL:
    out = Path(tempfile.gettempdir()) / "libgbasigner_eth_abi.so"
    cmd = [
        "gcc", "-O2", "-fPIC", "-shared", "-Wall", "-Wextra",
        "-include", str(SRC / "shim_host.h"),
        "-I", str(SRC),
        "-I", str(SRC / "crypto"),
        str(SRC / "crypto" / "eth_abi.c"),
        "-o", str(out),
    ]
    subprocess.run(cmd, check=True)
    lib = ctypes.CDLL(str(out))
    lib.eth_abi_decode.argtypes = [
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.c_uint32,
        ctypes.POINTER(EthAbiCall),
    ]
    lib.eth_abi_decode.restype = ctypes.c_int
    return lib


def decode(lib, data: bytes) -> tuple[int, EthAbiCall]:
    out = EthAbiCall()
    buf = (ctypes.c_uint8 * len(data))(*data)
    rc = lib.eth_abi_decode(buf, len(data), ctypes.byref(out))
    return rc, out


def pad_addr(addr_hex: str) -> bytes:
    """ABI padding: 12 bytes 0x00 + 20 bytes address."""
    a = bytes.fromhex(addr_hex.removeprefix("0x"))
    assert len(a) == 20
    return b"\x00" * 12 + a


def be_uint256(value: int) -> bytes:
    return value.to_bytes(32, "big")


def check(name: str, cond: bool, extra: str = "") -> int:
    if cond:
        print(f"[OK]  {name}")
        return 0
    print(f"[FAIL] {name}  {extra}")
    return 1


def main() -> int:
    print("compiling eth_abi as shared lib...")
    lib = build_lib()

    failures = 0
    TO = "AaBbCcDdEeFf00112233445566778899aAbBcCdD"
    FROM = "1111111111111111111111111111111111111111"
    SPENDER = "2222222222222222222222222222222222222222"
    OPERATOR = "3333333333333333333333333333333333333333"

    # ---- transfer ----
    data = bytes.fromhex("a9059cbb") + pad_addr(TO) + be_uint256(1500000)
    rc, c = decode(lib, data)
    failures += check("rc=1 transfer", rc == 1)
    failures += check("kind=TRANSFER", c.kind == TRANSFER, f"got {c.kind}")
    failures += check("addr_a=TO", bytes(c.addr_a).hex() == TO.lower())
    val = int.from_bytes(bytes(c.value_be), "big")
    failures += check(f"value=1500000", val == 1500000, f"got {val}")
    failures += check("is_infinite=0", c.is_infinite == 0)
    failures += check("has_addr_b=0", c.has_addr_b == 0)

    # ---- approve normal ----
    data = bytes.fromhex("095ea7b3") + pad_addr(SPENDER) + be_uint256(42)
    rc, c = decode(lib, data)
    failures += check("rc=1 approve", rc == 1)
    failures += check("kind=APPROVE", c.kind == APPROVE)
    failures += check("addr_a=SPENDER", bytes(c.addr_a).hex() == SPENDER.lower())
    failures += check("is_infinite=0 normal", c.is_infinite == 0)

    # ---- approve INFINITE ----
    data = bytes.fromhex("095ea7b3") + pad_addr(SPENDER) + b"\xff" * 32
    rc, c = decode(lib, data)
    failures += check("rc=1 approve infinite", rc == 1)
    failures += check("kind=APPROVE infinite", c.kind == APPROVE)
    failures += check("is_infinite=1", c.is_infinite == 1)

    # ---- transferFrom ----
    data = (bytes.fromhex("23b872dd")
            + pad_addr(FROM) + pad_addr(TO) + be_uint256(999))
    rc, c = decode(lib, data)
    failures += check("rc=1 transferFrom", rc == 1)
    failures += check("kind=TRANSFER_FROM", c.kind == TRANSFER_FROM)
    failures += check("addr_a=FROM", bytes(c.addr_a).hex() == FROM.lower())
    failures += check("addr_b=TO", bytes(c.addr_b).hex() == TO.lower())
    failures += check("has_addr_b=1", c.has_addr_b == 1)
    val = int.from_bytes(bytes(c.value_be), "big")
    failures += check("value=999", val == 999)

    # ---- safeTransferFrom (ERC-721) ----
    data = (bytes.fromhex("42842e0e")
            + pad_addr(FROM) + pad_addr(TO) + be_uint256(123456))
    rc, c = decode(lib, data)
    failures += check("rc=1 safeTransferFrom", rc == 1)
    failures += check("kind=SAFE_TRANSFER_FROM", c.kind == SAFE_TRANSFER_FROM)
    failures += check("addr_a=FROM (safe)", bytes(c.addr_a).hex() == FROM.lower())
    failures += check("addr_b=TO (safe)", bytes(c.addr_b).hex() == TO.lower())

    # ---- setApprovalForAll(operator, true) ----
    data = (bytes.fromhex("a22cb465")
            + pad_addr(OPERATOR) + be_uint256(1))
    rc, c = decode(lib, data)
    failures += check("rc=1 setApprovalForAll(true)", rc == 1)
    failures += check("kind=SET_APPROVAL_FOR_ALL", c.kind == SET_APPROVAL_FOR_ALL)
    failures += check("addr_a=OPERATOR", bytes(c.addr_a).hex() == OPERATOR.lower())
    failures += check("approved_bool=1", c.approved_bool == 1)

    # ---- setApprovalForAll(operator, false) ----
    data = (bytes.fromhex("a22cb465")
            + pad_addr(OPERATOR) + be_uint256(0))
    rc, c = decode(lib, data)
    failures += check("rc=1 setApprovalForAll(false)", rc == 1)
    failures += check("approved_bool=0", c.approved_bool == 0)

    # ============ MALFORMED CASES (should reject) ============

    # ---- wrong length ----
    data = bytes.fromhex("a9059cbb") + pad_addr(TO)  # missing value
    rc, _ = decode(lib, data)
    failures += check("reject short transfer", rc == 0)

    data = bytes.fromhex("a9059cbb") + pad_addr(TO) + be_uint256(1) + b"\x00"
    rc, _ = decode(lib, data)
    failures += check("reject extra byte", rc == 0)

    # ---- bad address padding (dirty bytes in high 12) ----
    dirty = b"\x00" * 11 + b"\x01" + bytes.fromhex(TO)  # byte 11 = 0x01
    data = bytes.fromhex("a9059cbb") + dirty + be_uint256(1)
    rc, _ = decode(lib, data)
    failures += check("reject dirty address padding", rc == 0)

    # ---- setApprovalForAll with bool=2 (invalid) ----
    data = bytes.fromhex("a22cb465") + pad_addr(OPERATOR) + be_uint256(2)
    rc, _ = decode(lib, data)
    failures += check("reject bool=2", rc == 0)

    # ---- setApprovalForAll with bool=high-byte set ----
    bad_bool = b"\x00" * 31 + b"\xff"
    data = bytes.fromhex("a22cb465") + pad_addr(OPERATOR) + bad_bool
    rc, _ = decode(lib, data)
    failures += check("reject bool=0xff", rc == 0)

    # ---- unknown selector ----
    data = bytes.fromhex("deadbeef") + pad_addr(TO) + be_uint256(1)
    rc, _ = decode(lib, data)
    failures += check("reject unknown selector", rc == 0)

    # ---- empty data ----
    rc, _ = decode(lib, b"")
    failures += check("reject empty data", rc == 0)

    # ---- data < 4 bytes ----
    rc, _ = decode(lib, b"\xa9\x05\x9c")
    failures += check("reject <4 bytes", rc == 0)

    print()
    if failures:
        print(f"=== {failures} failures ===")
        return 1
    print("=== ALL OK ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
