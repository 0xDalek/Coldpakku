"""Recuperación del recovery id (v) probando 0/1, normalizando a low-s.

El GBA escribe v = 0xFE como sentinel; aquí intentamos recuperar la
address con cada candidato y devolvemos el v correcto.

Adicionalmente normalizamos a low-s (EIP-2): si s > n/2, sustituimos
s' = n - s y volteamos el bit y_parity. uECC no garantiza low-s en sus
firmas y los nodos Ethereum (Geth, Erigon, etc.) rechazan firmas con s
en el upper half desde Homestead.
"""
from __future__ import annotations

from typing import Optional, Tuple

from eth_keys import keys
from eth_keys.exceptions import BadSignature

# Orden del subgrupo secp256k1
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_HALF_N = SECP256K1_N // 2


def normalize_low_s(r: int, s: int, recid: int) -> Tuple[int, int, int]:
    """Devuelve (r, s, recid) con s en lower half. Voltea recid si normaliza."""
    if s > SECP256K1_HALF_N:
        s = SECP256K1_N - s
        recid ^= 1
    return r, s, recid


def recover_address(hash32: bytes, sig65: bytes, expected_addr: bytes) -> Optional[Tuple[bytes, int]]:
    """Devuelve (sig_canonical_65, recid) si encuentra match, o None.

    `sig_canonical_65` ya viene con s en lower half y recid coherente,
    listo para meter en assemble_signed_rlp."""
    if len(sig65) != 65:
        raise ValueError("sig debe ser 65 bytes")
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
