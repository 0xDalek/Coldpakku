"""Raspberry Pi bridge: exposes the UART to the PC over a TCP socket.

Run on the Pi:
    python3 pc/pi_bridge.py --uart /dev/ttyS0 --listen 0.0.0.0:5555

From the PC, set up the SSH tunnel and use it as if it were a local mGBA:
    ssh -L 12345:127.0.0.1:5555 pi@raspi.local
    # In another shell on the PC:
    python3 pc/metamask_inject.py --port 12345 --rpc http://...
"""
from __future__ import annotations

import argparse
import select
import socket
import sys
import threading

import serial


def relay(src: callable, dst: callable, label: str, stop: threading.Event) -> None:
    while not stop.is_set():
        try:
            data = src()
        except Exception as e:
            print(f"[bridge] {label} done: {e}")
            stop.set()
            return
        if not data:
            continue
        try:
            dst(data)
        except Exception as e:
            print(f"[bridge] {label} write done: {e}")
            stop.set()
            return


def serve_one(ser: serial.Serial, conn: socket.socket) -> None:
    stop = threading.Event()

    def from_serial() -> bytes:
        # readN with a short timeout so the loop can exit
        return ser.read(256)

    def to_socket(b: bytes) -> None:
        conn.sendall(b)

    def from_socket() -> bytes:
        r, _, _ = select.select([conn], [], [], 0.1)
        if not r: return b""
        return conn.recv(256)

    def to_serial(b: bytes) -> None:
        ser.write(b); ser.flush()

    t1 = threading.Thread(target=relay, args=(from_serial, to_socket, "ser->sock", stop), daemon=True)
    t2 = threading.Thread(target=relay, args=(from_socket, to_serial, "sock->ser", stop), daemon=True)
    t1.start(); t2.start()
    stop.wait()
    try: conn.close()
    except Exception: pass


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--uart", default="/dev/ttyS0")
    p.add_argument("--baud", type=int, default=115200)
    p.add_argument("--listen", default="0.0.0.0:5555")
    args = p.parse_args()

    host, port = args.listen.split(":"); port = int(port)
    ser = serial.Serial(args.uart, baudrate=args.baud, bytesize=8,
                         parity=serial.PARITY_NONE, stopbits=1, timeout=0.1)
    print(f"[bridge] UART {args.uart} @ {args.baud} open")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port)); s.listen(1)
    print(f"[bridge] listening on TCP {host}:{port}")
    while True:
        conn, addr = s.accept()
        print(f"[bridge] client connected from {addr}")
        try:
            serve_one(ser, conn)
        finally:
            print(f"[bridge] client disconnected")


if __name__ == "__main__":
    sys.exit(main())
