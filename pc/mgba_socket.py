"""Cliente del socket TCP que expone mGBA con la opción `-l <addr>:<port>`.

mGBA expone el link cable como un socket TCP cuando se arranca con esta
flag. Cada lectura de un byte por el GBA equivale a recibir un byte del
socket; cada escritura del GBA aparece en el socket. Es decir, el host
actúa como "el otro GBA" del cable.

Uso típico (en otro shell):

    mgba -l 0.0.0.0:12345 gba-signer.gba

Y luego en Python:

    transport = MgbaSocketTransport("127.0.0.1", 12345)
    sig = perform_signing(transport, tx)
"""
from __future__ import annotations

import socket

from protocol import GbaTransport


class MgbaSocketTransport(GbaTransport):
    def __init__(self, host: str = "127.0.0.1", port: int = 12345):
        self.sock = socket.create_connection((host, port), timeout=60.0)

    def read(self, n: int, timeout_s: float = 30.0) -> bytes:
        self.sock.settimeout(timeout_s)
        out = bytearray()
        while len(out) < n:
            chunk = self.sock.recv(n - len(out))
            if not chunk:
                raise EOFError("socket cerrado por el peer")
            out += chunk
        return bytes(out)

    def write(self, data: bytes) -> None:
        self.sock.sendall(data)

    def close(self) -> None:
        try:
            self.sock.close()
        except Exception:
            pass
