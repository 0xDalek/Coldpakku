"""Client for the TCP socket mGBA exposes with the `-l <addr>:<port>` flag.

mGBA exposes the link cable as a TCP socket when started with this flag.
Every byte the GBA reads is a byte received from the socket; every byte
the GBA writes appears on the socket. In other words, the host plays the
role of "the other GBA" on the cable.

Typical usage (in another shell):

    mgba -l 0.0.0.0:12345 gba-signer.gba

Then in Python:

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
                raise EOFError("socket closed by peer")
            out += chunk
        return bytes(out)

    def write(self, data: bytes) -> None:
        self.sock.sendall(data)

    def close(self) -> None:
        try:
            self.sock.close()
        except Exception:
            pass
