# Throwaway UART debugger to diagnose the Link <-> Pico cable.
#
# Replaces the bridge's main.py while debugging. Every second it prints
# how many bytes it read from UART0 plus a hex dump of the first chunk.
# It also tries several baudrates in case the speed is wrong.
#
# Usage (host):
#   PYTHONPATH=.venv-tools python3 -m mpremote connect /dev/ttyACM0 cp pico/uart_debug.py :main.py
#   reset and listen with `cat /dev/ttyACM0`

import sys
import time
import micropython
from machine import UART, Pin

micropython.kbd_intr(-1)

# Try 115200 first (what we expect from the GBA in UART SIO mode)
print("=== UART DEBUG ===")
print("rescue window 2s (Ctrl-C for REPL)")
for _ in range(20):
    time.sleep_ms(100)
print("window closed, kbd_intr disabled")

BAUDRATES = [115200, 57600, 38400, 9600]
b_idx = 0

uart = UART(0, baudrate=BAUDRATES[b_idx], bits=8, parity=None, stop=1,
            tx=Pin(0), rx=Pin(1), timeout=0, rxbuf=2048)
print("listening on UART0 at", BAUDRATES[b_idx], "baud")

last_report = time.ticks_ms()
total_bytes = 0
sample = bytearray()

while True:
    n = uart.any()
    if n:
        chunk = uart.read(min(n, 64))
        if chunk:
            total_bytes += len(chunk)
            if len(sample) < 32:
                sample.extend(chunk[:32 - len(sample)])
    if time.ticks_diff(time.ticks_ms(), last_report) >= 1000:
        last_report = time.ticks_ms()
        if total_bytes:
            print("baud", BAUDRATES[b_idx], ": +", total_bytes, "bytes  hex:",
                  " ".join("%02x" % b for b in sample[:16]))
            sample = bytearray()
            total_bytes = 0
        else:
            print("baud", BAUDRATES[b_idx], ": 0 bytes (silence)")
            # after 5s of silence, try the next baudrate
            try:
                uart_silence_count
            except NameError:
                uart_silence_count = 0
            uart_silence_count += 1
            if uart_silence_count >= 5:
                uart_silence_count = 0
                b_idx = (b_idx + 1) % len(BAUDRATES)
                print("=== rotating to baud", BAUDRATES[b_idx])
                uart.deinit()
                uart = UART(0, baudrate=BAUDRATES[b_idx], bits=8, parity=None,
                            stop=1, tx=Pin(0), rx=Pin(1), timeout=0, rxbuf=2048)
