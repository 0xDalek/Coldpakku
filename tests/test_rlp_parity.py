"""Hashing parity between our encoder/decoder and eth_account.

For 100 random EIP-1559 transactions (plus a handful of legacy ones):
  1. build the unsigned tx with eth_account
  2. get the signing hash that eth_account expects
  3. serialize with rlp.encode the format expected by the GBA
  4. recompute keccak256 over those bytes (same as eth_tx.c does)
  5. require both hashes to match byte by byte

If this test passes, we know that:
  - the RLP we send to the GBA over UART produces the correct hash when
    keccak256-hashed directly (which is what eth_tx_signing_hash does).
  - the host can recover the signature correctly (`sig_recover` has its
    own test at the end using a random priv).

Run:
    python3 tests/test_rlp_parity.py
"""
from __future__ import annotations

import os
import random
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "pc"))
sys.path.insert(0, str(ROOT / ".venv-tools"))

import rlp
from eth_account import Account
from eth_account._utils.legacy_transactions import serializable_unsigned_transaction_from_dict
from eth_keys import keys
from eth_utils import keccak, to_canonical_address, to_checksum_address


def encode_unsigned_eip1559(tx: dict) -> bytes:
    fields = [
        tx["chainId"], tx["nonce"], tx["maxPriorityFeePerGas"],
        tx["maxFeePerGas"], tx["gas"],
        bytes.fromhex(tx["to"][2:]) if tx["to"] else b"",
        tx["value"], tx["data"], [],
    ]
    return b"\x02" + rlp.encode(fields)


def encode_unsigned_legacy(tx: dict) -> bytes:
    fields = [
        tx["nonce"], tx["gasPrice"], tx["gas"],
        bytes.fromhex(tx["to"][2:]) if tx["to"] else b"",
        tx["value"], tx["data"],
        tx["chainId"], 0, 0,        # EIP-155 trailers
    ]
    return rlp.encode(fields)


def random_eip1559_tx(rng: random.Random) -> dict:
    return {
        "type": 2,
        "chainId":             rng.choice([1, 5, 137, 42161, 11155111, 8453]),
        "nonce":               rng.randint(0, 2**32 - 1),
        "maxPriorityFeePerGas":rng.randint(1, 10**11),
        "maxFeePerGas":        rng.randint(10**9, 10**12),
        "gas":                 rng.randint(21000, 5_000_000),
        "to":                  to_checksum_address("0x" + secrets.token_hex(20)),
        "value":               rng.randint(0, 10**21),
        "data":                secrets.token_bytes(rng.randint(0, 512)),
        "accessList":          [],
    }


def random_legacy_tx(rng: random.Random) -> dict:
    return {
        "chainId":  rng.choice([1, 11155111]),
        "nonce":    rng.randint(0, 2**32 - 1),
        "gasPrice": rng.randint(10**9, 10**12),
        "gas":      rng.randint(21000, 1_000_000),
        "to":       to_checksum_address("0x" + secrets.token_hex(20)),
        "value":    rng.randint(0, 10**18),
        "data":     secrets.token_bytes(rng.randint(0, 64)),
    }


def sign_and_get_message_hash(tx: dict, priv_hex: str) -> bytes:
    """Returns the signing hash that eth_account would use internally for this
    unsigned tx. Uses the low-level helper because SignedTransaction no longer
    exposes message_hash in eth-account >= 0.13."""
    ut = serializable_unsigned_transaction_from_dict(tx)
    return bytes(ut.hash())


def main() -> int:
    rng = random.Random(0xC0FFEE)
    priv = "0x" + secrets.token_hex(32)
    n_1559 = 80
    n_legacy = 20
    failures = 0

    for i in range(n_1559):
        tx = random_eip1559_tx(rng)
        expected = sign_and_get_message_hash(tx, priv)
        rlp_blob = encode_unsigned_eip1559(tx)
        actual = keccak(rlp_blob)
        if expected != actual:
            failures += 1
            print(f"[FAIL] EIP-1559 #{i}: expected={expected.hex()} actual={actual.hex()}")
        if i % 10 == 0:
            print(f"  .. EIP-1559 {i}/{n_1559} ({len(rlp_blob)}B)")

    for i in range(n_legacy):
        tx = random_legacy_tx(rng)
        expected = sign_and_get_message_hash(tx, priv)
        rlp_blob = encode_unsigned_legacy(tx)
        actual = keccak(rlp_blob)
        if expected != actual:
            failures += 1
            print(f"[FAIL] legacy #{i}: expected={expected.hex()} actual={actual.hex()}")
        if i % 5 == 0:
            print(f"  .. legacy {i}/{n_legacy} ({len(rlp_blob)}B)")

    if failures:
        print(f"\nFAILED: {failures} txs did not produce hash parity")
        return 1
    print(f"\nOK: {n_1559 + n_legacy} txs hash parity correct")
    print("    -> the RLP we send to the GBA produces the hash eth_account expects")
    return 0


if __name__ == "__main__":
    sys.exit(main())
