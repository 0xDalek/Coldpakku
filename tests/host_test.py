"""Test the crypto modules compiled as a native (host) binary.

Compile the pure C99 .c files with host gcc (not devkitARM) and expose them
via ctypes to validate them against official vectors:

  - SHA-512                : RFC 4231
  - HMAC-SHA-512           : RFC 4231
  - PBKDF2-HMAC-SHA-512    : trezor mnemonic vector
  - Keccak-256             : "" -> c5d2..., "abc" -> 4e03...
  - BIP39 mnemonic→seed    : trezor "abandon...about"
  - BIP32 m/44'/60'/0'/0/0 : derivation to a known Ethereum address
  - ChaCha20               : RFC 8439 §2.4.2
  - EIP-712 (v7 parser)    : ERC-2612 Permit, Permit2 PermitSingle,
                             tamper detection, array rejection

This test does NOT need devkitARM or mGBA. It just validates the correctness
of the C code before running it on the GBA.

Usage:
    python3 tests/host_test.py
"""
from __future__ import annotations

import ctypes
import hashlib
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
TP = ROOT / "third_party"


def build_lib() -> ctypes.CDLL:
    cc = os.environ.get("CC", "gcc")
    sources = [
        SRC / "crypto/sha512.c",
        SRC / "crypto/hmac_sha512.c",
        SRC / "crypto/pbkdf2.c",
        SRC / "crypto/keccak256.c",
        SRC / "crypto/bip39.c",
        SRC / "crypto/bip32.c",
        SRC / "crypto/ethereum.c",
        SRC / "crypto/chacha20.c",
        SRC / "crypto/eip712.c",
        TP / "crypto-algorithms/sha256.c",
        TP / "micro-ecc/uECC.c",
    ]
    out = Path(tempfile.gettempdir()) / "libgbasigner_host.so"
    cmd = [
        cc, "-O2", "-fPIC", "-shared",
        "-Wno-unterminated-string-initialization",
        "-Wno-missing-braces",
        "-DuECC_PLATFORM=0",
        "-DuECC_OPTIMIZATION_LEVEL=2",
        "-DuECC_SUPPORTS_secp160r1=0",
        "-DuECC_SUPPORTS_secp192r1=0",
        "-DuECC_SUPPORTS_secp224r1=0",
        "-DuECC_SUPPORTS_secp256r1=0",
        "-DuECC_SUPPORTS_secp256k1=1",
        "-DuECC_SUPPORT_COMPRESSED_POINT=1",
        "-include", str(SRC / "shim_host.h"),
        "-I", str(SRC),
        "-I", str(SRC / "crypto"),
        "-I", str(TP / "micro-ecc"),
        "-I", str(TP / "crypto-algorithms"),
        *[str(p) for p in sources],
        "-o", str(out),
    ]
    subprocess.run(cmd, check=True)
    return ctypes.CDLL(str(out))


def main() -> int:
    print("compiling host library...")
    try:
        lib = build_lib()
    except FileNotFoundError as e:
        print(f"[SKIP] host C compiler not available ({e}).")
        print("       Install gcc (sudo apt install gcc) or set CC=<compiler> to run host tests.")
        return 0

    failures = 0

    # ---- SHA-512 ----
    out = (ctypes.c_uint8 * 64)()
    lib.sha512.argtypes = [ctypes.c_char_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint8)]
    lib.sha512(b"abc", 3, out)
    actual = bytes(out).hex()
    expected = hashlib.sha512(b"abc").hexdigest()
    if actual == expected:
        print("[OK]  sha512('abc')")
    else:
        print(f"[FAIL] sha512: got {actual} expected {expected}")
        failures += 1

    # ---- HMAC-SHA-512 (RFC 4231 test 1) ----
    out2 = (ctypes.c_uint8 * 64)()
    lib.hmac_sha512.argtypes = [ctypes.c_char_p, ctypes.c_uint32,
                                ctypes.c_char_p, ctypes.c_uint32,
                                ctypes.POINTER(ctypes.c_uint8)]
    key = b"\x0b" * 20
    msg = b"Hi There"
    lib.hmac_sha512(key, 20, msg, len(msg), out2)
    expected = "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
    actual = bytes(out2).hex()
    if actual == expected:
        print("[OK]  HMAC-SHA512 RFC4231 test 1")
    else:
        print(f"[FAIL] HMAC-SHA512: got {actual}")
        failures += 1

    # ---- PBKDF2-HMAC-SHA512 (BIP39 abandon...about) ----
    out3 = (ctypes.c_uint8 * 64)()
    lib.pbkdf2_hmac_sha512_64.argtypes = [
        ctypes.c_char_p, ctypes.c_uint32,
        ctypes.c_char_p, ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.c_void_p, ctypes.c_void_p,
    ]
    mnemonic = (("abandon " * 11) + "about").encode()
    salt = b"mnemonic"
    lib.pbkdf2_hmac_sha512_64(mnemonic, len(mnemonic), salt, len(salt), 2048, out3, None, None)
    expected_seed = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
    actual = bytes(out3).hex()
    if actual == expected_seed:
        print("[OK]  PBKDF2 BIP39 abandon×11 about → seed")
    else:
        print(f"[FAIL] PBKDF2: got {actual}\n     want {expected_seed}")
        failures += 1

    # ---- Keccak-256 ----
    out4 = (ctypes.c_uint8 * 32)()
    lib.keccak256.argtypes = [ctypes.c_char_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint8)]
    lib.keccak256(b"", 0, out4)
    actual = bytes(out4).hex()
    expected = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    if actual == expected:
        print("[OK]  keccak256('')")
    else:
        print(f"[FAIL] keccak256(''): got {actual}")
        failures += 1
    lib.keccak256(b"abc", 3, out4)
    actual = bytes(out4).hex()
    expected = "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
    if actual == expected:
        print("[OK]  keccak256('abc')")
    else:
        print(f"[FAIL] keccak256('abc'): got {actual}")
        failures += 1

    # ---- BIP32 → Ethereum address ----
    # Vector: mnemonic abandon×11 about, empty passphrase, m/44'/60'/0'/0/0
    # → known address = 0x9858EfFD232B4033E47d90003D41EC34EcaEda94 (trezor vector)
    seed = bytes(out3)  # we already have the BIP39 seed
    lib.bip32_master.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.c_void_p]
    lib.bip32_derive_eth_default.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    lib.bip32_derive_eth_default.restype = ctypes.c_int
    lib.eth_priv_to_address.argtypes = [
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.POINTER(ctypes.c_uint8),
    ]
    lib.eth_priv_to_address.restype = ctypes.c_int

    class Bip32Node(ctypes.Structure):
        _fields_ = [("priv", ctypes.c_uint8 * 32), ("chain", ctypes.c_uint8 * 32)]

    master = Bip32Node()
    child = Bip32Node()
    seed_buf = (ctypes.c_uint8 * 64)(*seed)
    lib.bip32_master(seed_buf, ctypes.byref(master))
    if not lib.bip32_derive_eth_default(ctypes.byref(master), ctypes.byref(child)):
        print("[FAIL] bip32 derive_eth_default returned 0")
        failures += 1
    else:
        addr = (ctypes.c_uint8 * 20)()
        if not lib.eth_priv_to_address(child.priv, addr, None):
            print("[FAIL] eth_priv_to_address returned 0")
            failures += 1
        else:
            actual = bytes(addr).hex()
            expected = "9858effd232b4033e47d90003d41ec34ecaeda94"
            if actual == expected:
                print(f"[OK]  BIP32 m/44'/60'/0'/0/0 → 0x{actual}")
            else:
                print(f"[FAIL] BIP32 address: got 0x{actual}\n     want 0x{expected}")
                failures += 1

    # ---- ChaCha20 (RFC 8439 §2.4.2) ----
    out5 = (ctypes.c_uint8 * 114)()
    lib.chacha20_xor.argtypes = [
        ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8), ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8), ctypes.c_uint32,
    ]
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    nonce = bytes.fromhex("000000000000004a00000000")
    plaintext = (b"Ladies and Gentlemen of the class of '99: If I could offer you "
                 b"only one tip for the future, sunscreen would be it.")
    pt = (ctypes.c_uint8 * len(plaintext))(*plaintext)
    out_buf = (ctypes.c_uint8 * len(plaintext))()
    key_buf = (ctypes.c_uint8 * 32)(*key)
    nonce_buf = (ctypes.c_uint8 * 12)(*nonce)
    lib.chacha20_xor(key_buf, nonce_buf, 1, pt, out_buf, len(plaintext))
    expected = "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d"
    actual = bytes(out_buf).hex()
    if actual == expected:
        print("[OK]  ChaCha20 RFC 8439 §2.4.2")
    else:
        print(f"[FAIL] ChaCha20: got {actual}\n     want {expected}")
        failures += 1

    # ---- ECDSA RFC 6979 (deterministic signature + recover) ----
    lib.eth_sign_hash.argtypes = [
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.POINTER(ctypes.c_uint8),
    ]
    lib.eth_sign_hash.restype = ctypes.c_int
    h = hashlib.sha256(b"hello world from coldpakku host test").digest()
    h_buf = (ctypes.c_uint8 * 32)(*h)
    sig_buf = (ctypes.c_uint8 * 65)()
    if not lib.eth_sign_hash(child.priv, h_buf, sig_buf):
        print("[FAIL] eth_sign_hash returned 0")
        failures += 1
    else:
        sig = bytes(sig_buf)
        # Import host lib for recover; if missing, skip
        try:
            from eth_keys import keys
            r = sig[:32]; s = sig[32:64]
            for recid in (0, 1):
                sigobj = keys.Signature(vrs=(recid, int.from_bytes(r, "big"), int.from_bytes(s, "big")))
                pub = sigobj.recover_public_key_from_msg_hash(h)
                if pub.to_canonical_address() == bytes(addr):
                    print(f"[OK]  ECDSA RFC 6979 sign + recover (recid={recid})")
                    break
            else:
                print("[FAIL] could not recover address with recid 0/1")
                failures += 1
        except ImportError:
            print("[SKIP] eth_keys not installed, cannot validate recover")

    # ---- EIP-712 v7 parser ----
    # Verify that the on-device parser, given the TLV the host serializer
    # produces, recomputes the same domainSeparator + messageHash that
    # eth_account computes. This is the trust anchor for the L+R combo
    # parsed view: a passing test here means the cartridge can detect a
    # malicious host that lies about which hashes a JSON corresponds to.
    try:
        sys.path.insert(0, str(ROOT / "pc"))
        from protocol import serialize_typed_data_tlv  # type: ignore
        from eth_account.messages import encode_typed_data  # type: ignore
    except ImportError as e:
        print(f"[SKIP] EIP-712 tests: missing dep ({e})")
    else:
        EIP712_OK_MATCH      = 0
        EIP712_OK_MISMATCH   = 1
        EIP712_ERR_MALFORMED = 2
        EIP712_ERR_UNSUPP    = 3
        EIP712_ERR_TOO_BIG   = 4

        # The parser owns a ~6.4 KB tree struct; 16 KB is plenty.
        lib.eip712_parse_and_verify.argtypes = [
            ctypes.POINTER(ctypes.c_uint8), ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_void_p,
        ]
        lib.eip712_parse_and_verify.restype = ctypes.c_int
        tree_buf = (ctypes.c_uint8 * 16384)()

        def run_parser(td: dict, mutate=None, expect=EIP712_OK_MATCH, label: str = ""):
            nonlocal failures
            tlv = serialize_typed_data_tlv(td)
            if mutate is not None:
                tlv = mutate(bytearray(tlv))
            sm = encode_typed_data(full_message=td)
            ds, mh = bytes(sm.header), bytes(sm.body)
            tlv_arr = (ctypes.c_uint8 * len(tlv)).from_buffer(bytearray(tlv))
            ds_arr  = (ctypes.c_uint8 * 32)(*ds)
            mh_arr  = (ctypes.c_uint8 * 32)(*mh)
            status = lib.eip712_parse_and_verify(tlv_arr, len(tlv), ds_arr, mh_arr, tree_buf)
            if status == expect:
                print(f"[OK]  EIP-712 {label}  (status={status})")
            else:
                names = {0: "OK_MATCH", 1: "OK_MISMATCH", 2: "ERR_MALFORMED",
                         3: "ERR_UNSUPPORTED", 4: "ERR_TOO_BIG"}
                print(f"[FAIL] EIP-712 {label}: got {names.get(status,status)} "
                      f"expected {names.get(expect,expect)}")
                failures += 1

        # 1) ERC-2612 Permit (USDC mainnet shape)
        permit_td = {
            "types": {
                "EIP712Domain": [
                    {"name": "name",              "type": "string"},
                    {"name": "version",           "type": "string"},
                    {"name": "chainId",           "type": "uint256"},
                    {"name": "verifyingContract", "type": "address"},
                ],
                "Permit": [
                    {"name": "owner",    "type": "address"},
                    {"name": "spender",  "type": "address"},
                    {"name": "value",    "type": "uint256"},
                    {"name": "nonce",    "type": "uint256"},
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
                "owner":    "0x1111111111111111111111111111111111111111",
                "spender":  "0x2222222222222222222222222222222222222222",
                "value":    1000000,
                "nonce":    0,
                "deadline": 1735689600,
            },
        }
        run_parser(permit_td, label="ERC-2612 Permit (USDC)")

        # 2) Permit2 PermitSingle — nested struct, depth 2
        permit2_td = {
            "types": {
                "EIP712Domain": [
                    {"name": "name",              "type": "string"},
                    {"name": "chainId",           "type": "uint256"},
                    {"name": "verifyingContract", "type": "address"},
                ],
                "PermitDetails": [
                    {"name": "token",      "type": "address"},
                    {"name": "amount",     "type": "uint160"},
                    {"name": "expiration", "type": "uint48"},
                    {"name": "nonce",      "type": "uint48"},
                ],
                "PermitSingle": [
                    {"name": "details",     "type": "PermitDetails"},
                    {"name": "spender",     "type": "address"},
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
                    "token":      "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
                    "amount":     1000000000000,
                    "expiration": 1735689600,
                    "nonce":      0,
                },
                "spender":     "0x3333333333333333333333333333333333333333",
                "sigDeadline": 1735776000,
            },
        }
        run_parser(permit2_td, label="Permit2 PermitSingle (nested)")

        # 3) Tamper detection: flip one byte of the message values and
        # expect OK_MISMATCH (parser still decodes, just doesn't match
        # the host-supplied hashes). We mutate after num_types/header so
        # the structure stays valid.
        def flip_last_byte(buf: bytearray) -> bytes:
            buf[-1] ^= 0x01
            return bytes(buf)
        run_parser(permit_td, mutate=flip_last_byte,
                   expect=EIP712_OK_MISMATCH,
                   label="ERC-2612 Permit — tampered deadline byte")

        # 4) Array support: v0.2 must refuse with ERR_UNSUPPORTED. We
        # build a Permit2 PermitBatch shape.
        permit2_batch_td = {
            "types": {
                "EIP712Domain": [
                    {"name": "name",              "type": "string"},
                    {"name": "chainId",           "type": "uint256"},
                    {"name": "verifyingContract", "type": "address"},
                ],
                "PermitDetails": [
                    {"name": "token",      "type": "address"},
                    {"name": "amount",     "type": "uint160"},
                    {"name": "expiration", "type": "uint48"},
                    {"name": "nonce",      "type": "uint48"},
                ],
                "PermitBatch": [
                    {"name": "details",     "type": "PermitDetails[]"},
                    {"name": "spender",     "type": "address"},
                    {"name": "sigDeadline", "type": "uint256"},
                ],
            },
            "primaryType": "PermitBatch",
            "domain": {
                "name": "Permit2",
                "chainId": 1,
                "verifyingContract": "0x000000000022D473030F116dDEE9F6B43aC78BA3",
            },
            "message": {
                "details": [
                    {
                        "token":      "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
                        "amount":     1000000,
                        "expiration": 1735689600,
                        "nonce":      0,
                    },
                    {
                        "token":      "0xdAC17F958D2ee523a2206206994597C13D831ec7",
                        "amount":     2000000,
                        "expiration": 1735689600,
                        "nonce":      1,
                    },
                ],
                "spender":     "0x3333333333333333333333333333333333333333",
                "sigDeadline": 1735776000,
            },
        }
        run_parser(permit2_batch_td, expect=EIP712_ERR_UNSUPP,
                   label="Permit2 PermitBatch (array) → UNSUPPORTED")

        # 5) Malformed TLV: truncate the values blob.
        def truncate_half(buf: bytearray) -> bytes:
            return bytes(buf[: len(buf) // 2])
        run_parser(permit_td, mutate=truncate_half,
                   expect=EIP712_ERR_MALFORMED,
                   label="Truncated TLV → MALFORMED")

    print()
    if failures:
        print(f"=== {failures} failures ===")
        return 1
    print("=== ALL OK ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
