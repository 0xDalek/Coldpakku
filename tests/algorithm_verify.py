"""Verify that the derivation chain implemented by the GBA's .c files produces
the values expected by the official vectors and by reference libraries
(bip_utils, eth_account).

This test does NOT execute the C code — for that see host_test.py, which
requires native gcc. Here what we do is:

  1. Compute the BIP39 seed, BIP32 master, m/44'/60'/0'/0/0 derivation and the
     Ethereum address using hashlib + reference libraries.
  2. Compare against the "abandon×11 about" vector (the expected address).
  3. Generate `tests/golden_values.json` with all intermediate values that
     the GBA must produce; useful as a "snapshot test" when running on mGBA.

Usage:
    PYTHONPATH=.venv-tools python3 tests/algorithm_verify.py
"""
from __future__ import annotations

import hashlib
import hmac
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# --- official BIP39 vectors ----------------------------------------------------
MNEMONIC = " ".join(["abandon"] * 11 + ["about"])
PASSPHRASE = ""
EXPECTED_SEED_HEX = (
    "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1"
    "9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
)
EXPECTED_ETH_ADDRESS = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"


def pbkdf2_seed(mnemonic: str, passphrase: str) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha512",
        mnemonic.encode("utf-8"),
        ("mnemonic" + passphrase).encode("utf-8"),
        2048,
        64,
    )


def hmac_sha512(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha512).digest()


# --- BIP32 derivation (mirror of bip32.c) -------------------------------------
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def bip32_master(seed: bytes) -> tuple[bytes, bytes]:
    I = hmac_sha512(b"Bitcoin seed", seed)
    return I[:32], I[32:]


def priv_to_pub_compressed(priv: bytes) -> bytes:
    """Returns the compressed public key (33 bytes)."""
    from ecdsa import SECP256k1, SigningKey
    sk = SigningKey.from_string(priv, curve=SECP256k1)
    vk = sk.verifying_key
    point = vk.pubkey.point
    x = point.x().to_bytes(32, "big")
    prefix = b"\x03" if (point.y() & 1) else b"\x02"
    return prefix + x


def bip32_ckd(priv: bytes, chain: bytes, index: int) -> tuple[bytes, bytes]:
    if index >= 0x80000000:
        data = b"\x00" + priv + index.to_bytes(4, "big")
    else:
        data = priv_to_pub_compressed(priv) + index.to_bytes(4, "big")
    I = hmac_sha512(chain, data)
    IL = int.from_bytes(I[:32], "big")
    if IL >= SECP256K1_N:
        raise ValueError("IL >= n")
    child_int = (IL + int.from_bytes(priv, "big")) % SECP256K1_N
    if child_int == 0:
        raise ValueError("child=0")
    return child_int.to_bytes(32, "big"), I[32:]


def derive_eth_default(master_priv: bytes, master_chain: bytes) -> bytes:
    """m/44'/60'/0'/0/0 → priv key 32B."""
    H = 0x80000000
    p, c = bip32_ckd(master_priv, master_chain, H + 44)
    p, c = bip32_ckd(p, c, H + 60)
    p, c = bip32_ckd(p, c, H + 0)
    p, c = bip32_ckd(p, c, 0)
    p, c = bip32_ckd(p, c, 0)
    return p


def priv_to_eth_address(priv: bytes) -> bytes:
    from ecdsa import SECP256k1, SigningKey
    sk = SigningKey.from_string(priv, curve=SECP256k1)
    vk = sk.verifying_key
    point = vk.pubkey.point
    pub64 = point.x().to_bytes(32, "big") + point.y().to_bytes(32, "big")
    # keccak256
    try:
        from Crypto.Hash import keccak as kc
        h = kc.new(digest_bits=256); h.update(pub64); k = h.digest()
    except ImportError:
        from eth_utils import keccak as ek
        k = ek(pub64)
    return k[12:]


def main() -> int:
    failures = 0

    # BIP39 → seed
    seed = pbkdf2_seed(MNEMONIC, PASSPHRASE)
    if seed.hex() == EXPECTED_SEED_HEX:
        print(f"[OK]  BIP39 seed (PBKDF2-HMAC-SHA512 2048): {seed[:8].hex()}...")
    else:
        print(f"[FAIL] BIP39 seed: got {seed.hex()}\n     want {EXPECTED_SEED_HEX}")
        failures += 1

    # BIP32 master
    mpriv, mchain = bip32_master(seed)
    print(f"      master priv  = {mpriv.hex()}")
    print(f"      master chain = {mchain.hex()}")

    # Derive m/44'/60'/0'/0/0
    eth_priv = derive_eth_default(mpriv, mchain)
    print(f"      eth priv     = {eth_priv.hex()}")

    # Address
    addr = priv_to_eth_address(eth_priv)
    addr_hex = "0x" + addr.hex()
    if addr_hex.lower() == EXPECTED_ETH_ADDRESS.lower():
        print(f"[OK]  ETH address {addr_hex} (== {EXPECTED_ETH_ADDRESS})")
    else:
        print(f"[FAIL] ETH address: got {addr_hex}\n     want {EXPECTED_ETH_ADDRESS}")
        failures += 1

    # Cross-check with eth_account
    try:
        from eth_account import Account
        Account.enable_unaudited_hdwallet_features()
        ea = Account.from_mnemonic(MNEMONIC, account_path="m/44'/60'/0'/0/0")
        if ea.address.lower() == addr_hex.lower():
            print(f"[OK]  eth_account.from_mnemonic = {ea.address}")
        else:
            print(f"[FAIL] eth_account: {ea.address} vs ours {addr_hex}")
            failures += 1
    except ImportError:
        print("[SKIP] eth_account not installed")

    # Write golden file
    golden = {
        "mnemonic": MNEMONIC,
        "passphrase": PASSPHRASE,
        "seed_hex": seed.hex(),
        "master_priv_hex": mpriv.hex(),
        "master_chain_hex": mchain.hex(),
        "eth_priv_hex": eth_priv.hex(),
        "eth_address": addr_hex,
        "derivation_path": "m/44'/60'/0'/0/0",
    }
    out = ROOT / "tests" / "golden_values.json"
    out.write_text(json.dumps(golden, indent=2) + "\n")
    print(f"      golden snapshot written to {out}")

    print()
    if failures:
        print(f"=== {failures} failures ===")
        return 1
    print("=== ALL OK ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
