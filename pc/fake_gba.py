"""Simulador del lado GBA del protocolo (v2 — RLP). Útil para iterar el lado
PC sin necesidad de tener mGBA arrancado, y para los tests de paridad RLP.

Acepta una conexión TCP, ejecuta el handshake nuevo:
  - lee opcode 0xCD + len_be(4) + bytes RLP
  - parsea con eth_account.Account.encode_typed_transaction (legacy: rlp directo)
  - calcula keccak256 y firma con la priv key dada

Ejecutar:
    python3 pc/fake_gba.py 12345 0xPRIVKEY_HEX
    # En otro shell:
    python3 pc/test_e2e.py 0xADDRESS_DERIVADA_DE_LA_PRIVKEY
"""
from __future__ import annotations

import socket
import sys

from eth_keys import keys
from eth_utils import keccak

from protocol import (PROTO_ACK, PROTO_CANCEL, PROTO_DONE, PROTO_READY,
                      PROTO_TX_RLP, PROTO_TX_RLP_MAX, SIG_V_SENTINEL)


def parse_tx_summary(rlp_blob: bytes) -> str:
    """Sólo para imprimir info; no es un parser estricto.
    Usa eth_account si está disponible; si no, sólo dice el tamaño."""
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
    print("[fake_gba] READY enviado")

    ack = conn.recv(1)
    if not ack or ack[0] != PROTO_ACK:
        print(f"[fake_gba] esperaba ACK, recibi {ack!r}")
        return
    print("[fake_gba] ACK recibido")

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
        print(f"[fake_gba] opcode inesperado: {op:#04x}, esperaba TX_RLP {PROTO_TX_RLP:#04x}")
        return
    length = int.from_bytes(recv_n(4), "big")
    if length == 0 or length > PROTO_TX_RLP_MAX:
        print(f"[fake_gba] longitud invalida: {length}")
        return
    rlp_blob = recv_n(length)
    print(f"[fake_gba] tx RLP recibida ({length}B): {parse_tx_summary(rlp_blob)}")

    h = keccak(rlp_blob)
    print(f"[fake_gba] signing hash interno = 0x{h.hex()}")

    sig = sk.sign_msg_hash(h)
    rs = sig.r.to_bytes(32, "big") + sig.s.to_bytes(32, "big")
    conn.sendall(rs + bytes([SIG_V_SENTINEL]))
    print(f"[fake_gba] firma enviada: {rs.hex()}{SIG_V_SENTINEL:02x}")

    conn.sendall(bytes([PROTO_DONE]))
    print("[fake_gba] DONE enviado")


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__); return 2
    port = int(sys.argv[1]); priv_hex = sys.argv[2].removeprefix("0x")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(1)
    print(f"[fake_gba] escuchando en :{port}")
    while True:
        conn, addr = s.accept()
        print(f"[fake_gba] conexion desde {addr}")
        try:
            handle(conn, priv_hex)
        except Exception as e:
            print(f"[fake_gba] error: {e}")
        finally:
            conn.close()


if __name__ == "__main__":
    sys.exit(main())
