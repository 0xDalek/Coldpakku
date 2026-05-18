"""Simulator of the GBA side of the protocol (v2 — RLP). Useful to iterate
on the PC side without having mGBA running, and for the RLP parity tests.

Accepts a TCP connection, runs the new handshake:
  - reads opcode 0xCD + len_be(4) + RLP bytes
  - parses with eth_account.Account.encode_typed_transaction (legacy: rlp directly)
  - computes keccak256 and signs with the given priv key

Run:
    python3 pc/fake_gba.py 12345 0xPRIVKEY_HEX
    # In another shell:
    python3 pc/test_e2e.py 0xADDRESS_DERIVED_FROM_THE_PRIVKEY
"""
from __future__ import annotations

import socket
import sys

from eth_keys import keys
from eth_utils import keccak

from protocol import (PROTO_ACK, PROTO_CANCEL, PROTO_DONE, PROTO_READY,
                      PROTO_TX_RLP, PROTO_TX_RLP_MAX, SIG_V_SENTINEL)


def parse_tx_summary(rlp_blob: bytes) -> str:
    """For display only; not a strict parser.
    Uses eth_account if available; otherwise just reports the size."""
    try:
        import rlp as rlp_lib
        if rlp_blob[0] == 0x02:
            decoded = rlp_lib.decode(rlp_blob[1:])
            chainid, nonce = int.from_bytes(decoded[0], "big"), int.from_bytes(decoded[1], "big")
            to = decoded[5].hex()
            value = int.from_bytes(decoded[6], "big")
            return (f"type=2 chainId={chainid} nonce={nonce} "
                    f"to=0x{to} value={value}")
        decoded = rlp_lib.decode(rlp_blob)
        return f"type=legacy fields={len(decoded)}"
    except Exception as e:
        return f"<unparsed: {e}>"


def handle(conn: socket.socket, priv_hex: str) -> None:
    sk = keys.PrivateKey(bytes.fromhex(priv_hex))

    conn.sendall(bytes([PROTO_READY]))
    print("[fake_gba] READY sent")

    ack = conn.recv(1)
    if not ack or ack[0] != PROTO_ACK:
        print(f"[fake_gba] expected ACK, got {ack!r}")
        return
    print("[fake_gba] ACK received")

    def recv_n(n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = conn.recv(n - len(buf))
            if not chunk:
                raise EOFError
            buf += chunk
        return buf

    op = recv_n(1)[0]
    if op != PROTO_TX_RLP:
        print(f"[fake_gba] unexpected opcode: {op:#04x}, expected TX_RLP {PROTO_TX_RLP:#04x}")
        return
    length = int.from_bytes(recv_n(4), "big")
    if length == 0 or length > PROTO_TX_RLP_MAX:
        print(f"[fake_gba] invalid length: {length}")
        return
    rlp_blob = recv_n(length)
    print(f"[fake_gba] tx RLP received ({length}B): {parse_tx_summary(rlp_blob)}")

    h = keccak(rlp_blob)
    print(f"[fake_gba] internal signing hash = 0x{h.hex()}")

    sig = sk.sign_msg_hash(h)
    rs = sig.r.to_bytes(32, "big") + sig.s.to_bytes(32, "big")
    conn.sendall(rs + bytes([SIG_V_SENTINEL]))
    print(f"[fake_gba] signature sent: {rs.hex()}{SIG_V_SENTINEL:02x}")

    conn.sendall(bytes([PROTO_DONE]))
    print("[fake_gba] DONE sent")


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__); return 2
    port = int(sys.argv[1]); priv_hex = sys.argv[2].removeprefix("0x")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(1)
    print(f"[fake_gba] listening on :{port}")
    while True:
        conn, addr = s.accept()
        print(f"[fake_gba] connection from {addr}")
        try:
            handle(conn, priv_hex)
        except Exception as e:
            print(f"[fake_gba] error: {e}")
        finally:
            conn.close()


if __name__ == "__main__":
    sys.exit(main())
