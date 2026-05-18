"""Recover the recovery id (v) by trying 0/1 and normalize to low-s.

The GBA writes v = 0xFE as a sentinel; here we try to recover the
address with each candidate and return the correct v.

We also normalize to low-s (EIP-2): if s > n/2, we substitute
s' = n - s and flip the y_parity bit. uECC does not guarantee low-s in
its signatures and Ethereum nodes (Geth, Erigon, etc.) reject signatures
with s in the upper half since Homestead.
"""
from __future__ import annotations

from typing import Optional, Tuple

from eth_keys import keys
from eth_keys.exceptions import BadSignature

# Order of the secp256k1 subgroup
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_HALF_N = SECP256K1_N // 2


def normalize_low_s(r: int, s: int, recid: int) -> Tuple[int, int, int]:
    """Return (r, s, recid) with s in the lower half. Flips recid when it normalizes."""
    if s > SECP256K1_HALF_N:
        s = SECP256K1_N - s
        recid ^= 1
    return r, s, recid


def recover_address(hash32: bytes, sig65: bytes, expected_addr: bytes) -> Optional[Tuple[bytes, int]]:
    """Return (sig_canonical_65, recid) if a match is found, else None.

    `sig_canonical_65` already has s in the lower half and a coherent
    recid, ready to feed into assemble_signed_rlp."""
    if len(sig65) != 65:
        raise ValueError("sig must be 65 bytes")
    r_int = int.from_bytes(sig65[:32], "big")
    s_int = int.from_bytes(sig65[32:64], "big")
    for recid in (0, 1):
        try:
            sig_obj = keys.Signature(vrs=(recid, r_int, s_int))
            pub = sig_obj.recover_public_key_from_msg_hash(hash32)
            if pub.to_canonical_address() != expected_addr:
                continue
            r_norm, s_norm, recid_norm = normalize_low_s(r_int, s_int, recid)
            canonical = (
                r_norm.to_bytes(32, "big")
                + s_norm.to_bytes(32, "big")
                + bytes([27 + recid_norm])
            )
            return canonical, recid_norm
        except BadSignature:
            continue
    return None
