# USB-CDC <-> UART0 bridge for Raspberry Pi Pico (RP2040).
#
# Replaces the old bridge based on a Raspberry Pi 3/4 + /dev/ttyS0.
# The Pico is natively 3.3V CMOS on GP0/GP1, the same electrical level
# as the GBA's SIO in UART mode, so NO level shifter is needed.
#
# Wiring (see docs/PICO_BRIDGE.md):
#   GBA pin 2 (SO, red)     -> Pico GP1 (UART0 RX)
#   GBA pin 3 (SI, orange)  -> Pico GP0 (UART0 TX)
#   GBA pin 6 (GND, blue)   -> Pico GND
#   GBA pin 1 (VDD)         -> NC (the Pico is powered over USB)
#
# Installation:
#   1. Flash MicroPython: grab the official UF2 from
#      https://micropython.org/download/RPI_PICO/ and drag it onto the
#      RPI-RP2 drive that appears when you press BOOTSEL.
#   2. Copy this file as `main.py` to the Pico's filesystem
#      (`mpremote cp pico/main.py :main.py`, or via Thonny).
#   3. Unplug and replug USB. It shows up as /dev/ttyACM0 (Linux) or
#      COMx (Windows). The bridge starts on its own at every boot.
#
# RESCUE WINDOW (important):
#   During the first 2 seconds after boot, Ctrl-C is NOT disabled. If
#   you press Ctrl-C inside `mpremote repl` during that window, the
#   script is interrupted and you land in the REPL so you can reflash
#   without going into BOOTSEL mode. After 2s, kbd_intr(-1) makes the
#   bridge immune to binary bytes (including 0x03) on stdin.
#
# Quick smoke-test (no GBA, loop TX-RX by jumpering GP0 to GP1):
#   python3 -c "import serial; s=serial.Serial('/dev/ttyACM0',115200); \
#                s.write(b'ping\\n'); print(s.read(5))"

import sys
import select
import time
import micropython
from machine import UART, Pin

# === 2-second rescue window (Ctrl-C still kills the script) ==============
print("gba-signer bridge: rescue window 2s (press Ctrl-C in REPL to abort)")
for i in range(20):
    time.sleep_ms(100)
print("gba-signer bridge: starting bridge mode")

# === Real bridge =========================================================
# CRITICAL: now disable the Ctrl-C interceptor on stdin. Without this any
# 0x03 byte coming over USB-CDC kills the loop. We are transporting
# binary RLP, so this is mandatory.
micropython.kbd_intr(-1)

uart = UART(
    0,
    baudrate=115200,
    bits=8,
    parity=None,
    stop=1,
    tx=Pin(0),
    rx=Pin(1),
    timeout=0,
    timeout_char=2,
    rxbuf=512,
    txbuf=512,
)

poller = select.poll()
poller.register(sys.stdin, select.POLLIN)

try:
    while True:
        # GBA -> PC: drain UART and flush to USB-CDC.
        if uart.any():
            chunk = uart.read(64)
            if chunk:
                sys.stdout.buffer.write(chunk)

        # PC -> GBA: read from USB-CDC (non-blocking via poll) and push to UART.
        # Important: use read1() so we don't block if poll() lies about the
        # number of available bytes. read() blocks waiting for the N bytes.
        if poller.poll(0):
            try:
                b = sys.stdin.buffer.read1(64)
            except AttributeError:
                # micropython without read1: fall back to read(1) (one byte at a time)
                b = sys.stdin.buffer.read(1)
            if b:
                uart.write(b)
except Exception as e:
    sys.stderr.write("bridge crash: %r\n" % e)
    time.sleep_ms(200)
    import machine
    machine.reset()
