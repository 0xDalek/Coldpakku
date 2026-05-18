"""Transport over /dev/ttyS0 (hardware UART) — used on the Raspberry Pi.

GBA link cable <-> Pi GPIO wiring:
    GBA SO  -> Pi GPIO15 (RXD0, pin 10)
    GBA SI  <- Pi GPIO14 (TXD0, pin 8)
    GBA SC  <- (unused in async UART mode)
    GBA SD  -> (ditto)
    GBA GND <-> Pi GND (pin 6, 9, etc.)

Do NOT connect the cable's Vcc to the Pi: the GBA is powered by its own
battery. If you only share GND, the GBA's 3.3V LVTTL levels are directly
compatible with the Pi's 3.3V GPIO pins (no level shifter needed for
Pi 1/2/3/4/5).

Enabling UART on the Pi:
    sudo raspi-config -> Interface -> Serial -> no login console, yes HW
    (or in /boot/config.txt: enable_uart=1, dtoverlay=disable-bt on Pi3+)
"""
from __future__ import annotations

import time

import serial

from protocol import GbaTransport


class SerialTransport(GbaTransport):
    """Transport over /dev/ttyACM0 (Pico USB-CDC bridge -> UART to the GBA).

    History:
      v1: the GBA's SIO in UART mode has a 4-byte RX FIFO and the
          original `uart_recv_byte_timeout` only drained it once per
          VBlank (~16 ms = 60 B/s). With bursts at 115200 baud the FIFO
          overflowed and we silently lost bytes.
      v2: the GBA firmware now busy-spins in `uart_recv_byte_busy`
          inside `protocol_recv_tx_rlp`, draining the FIFO at CPU rate
          (~MB/s). We no longer need aggressive host throttling.

    We keep a VERY light throttle (32 B / 0.5 ms = ~60 KB/s) for two
    defensive reasons:
      - the MicroPython bridge on the Pico polls and a giant burst could
        saturate the Pico's UART TX buffer (512 B).
      - it gives the GBA time between chunks to handle interrupts (for
        example if we ever add cooperative VBlank handling).
    If the GBA firmware improves further this can be raised/removed."""

    # The Pico USB-CDC resets when the port is opened if DTR/RTS toggles
    # (default pyserial behaviour on some Linux drivers). After the
    # reset the MicroPython bridge needs ~2.5s to boot (2s rescue
    # window + boot). If we start reading earlier we miss the GBA's
    # READYs and everything desyncs. Hence the initial wait.
    BOOT_SETTLE_S = 3.0

    def __init__(self, device: str = "/dev/ttyACM0", baudrate: int = 115200,
                 chunk_size: int = 32, chunk_delay_s: float = 0.0005,
                 boot_settle_s: float | None = None):
        self.ser = serial.Serial()
        self.ser.port = device
        self.ser.baudrate = baudrate
        self.ser.bytesize = 8
        self.ser.parity = serial.PARITY_NONE
        self.ser.stopbits = 1
        # Setting dtr/rts to False *before* open() reduces the toggle on
        # some drivers but does not eliminate it fully. That's why we
        # also have boot_settle_s.
        self.ser.dtr = False
        self.ser.rts = False
        self.ser.timeout = 30.0
        self.ser.open()

        self.chunk_size = chunk_size
        self.chunk_delay_s = chunk_delay_s

        # Wait for the Pico to finish booting after the (possible) reset
        # from open(). During this window the bytes the bridge forwards
        # are the GBA's first READY after being reconnected.
        settle = boot_settle_s if boot_settle_s is not None else self.BOOT_SETTLE_S
        if settle > 0:
            time.sleep(settle)

        # Drain any leftover bytes (READY pulses accumulated during the
        # Pico boot, leftovers from previous sessions, etc.). The next
        # read() will see a "fresh" READY.
        self._drain()

    def _drain(self, settle_s: float = 0.2) -> None:
        """Read bytes until nothing arrives for `settle_s` seconds."""
        old_to = self.ser.timeout
        try:
            self.ser.timeout = settle_s
            while True:
                chunk = self.ser.read(4096)
                if not chunk:
                    return
        finally:
            self.ser.timeout = old_to

    def read(self, n: int, timeout_s: float = 30.0) -> bytes:
        self.ser.timeout = timeout_s
        deadline = time.monotonic() + timeout_s
        out = bytearray()
        while len(out) < n:
            chunk = self.ser.read(n - len(out))
            if chunk:
                out += chunk
            elif time.monotonic() > deadline:
                raise TimeoutError(f"waiting for {n} bytes, received {len(out)}")
        return bytes(out)

    def write(self, data: bytes) -> None:
        # Chunk it up so we don't overflow the GBA's RX FIFO (4 bytes).
        for i in range(0, len(data), self.chunk_size):
            self.ser.write(data[i:i + self.chunk_size])
            self.ser.flush()
            if self.chunk_delay_s > 0:
                time.sleep(self.chunk_delay_s)

    def close(self) -> None:
        try:
            self.ser.close()
        except Exception:
            pass
