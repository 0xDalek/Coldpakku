"""E2E test over the mGBA socket: send an RLP-encoded EIP-1559 tx,
receive the signature, validate it.

Prerequisites:
  pip install -r requirements.txt
  mgba -l 0.0.0.0:12345 coldpakku.gba   (run in another terminal)
  On the GBA: finish mnemonic entry (or load a session) up to READY

Run:
  python3 pc/test_e2e.py 0xEXPECTED_ADDRESS
"""
from __future__ import annotations

import sys

import rlp
from eth_utils import keccak, to_canonical_address, to_checksum_address

from mgba_socket import MgbaSocketTransport
from protocol import RlpTx, perform_signing
from sig_recover import recover_address


def encode_unsigned_eip1559(chainid: int, nonce: int, max_priority: int,
                            max_fee: int, gas: int, to: bytes,
                            value: int, data: bytes) -> bytes:
    fields = [chainid, nonce, max_priority, max_fee, gas, to, value, data, []]
    return b"\x02" + rlp.encode(fields)


def main(expected_addr_hex: str, port: int = 12345) -> int:
    expected_addr = to_canonical_address(expected_addr_hex)

    to_addr = bytes.fromhex("00000000000000000000000000000000000000aa")
    value   = 1_000_000_000_000_000   # 0.001 ETH
    chainid = 11155111                  # Sepolia

    blob = encode_unsigned_eip1559(
        chainid=chainid, nonce=0,
        max_priority=1_500_000_000, max_fee=20_000_000_000,
        gas=21000, to=to_addr, value=value, data=b"",
    )
    h = keccak(blob)
    print(f"unsigned RLP ({len(blob)}B), hash = 0x{h.hex()}")

    tx = RlpTx(rlp=blob)

    print(f"connecting to 127.0.0.1:{port}...")
    t = MgbaSocketTransport(port=port)
    print(f"waiting for READY from the GBA...")
    sig = perform_signing(t, tx)
    if sig is None:
        print("user CANCELLED on the GBA")
        return 2

    print(f"signature received: {sig.hex()}")
    rec = recover_address(h, sig, expected_addr)
    if rec is None:
        print(f"ERROR: could not recover the expected address {to_checksum_address(expected_addr)}")
        return 3
    canonical, recid = rec
    print(f"OK: recid={recid}, canonical sig = {canonical.hex()}")
    print(f"recovered address = {to_checksum_address(expected_addr)}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    addr = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 12345
    sys.exit(main(addr, port))
