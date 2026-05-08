# UART debugger temporal para diagnosticar el cable Link <-> Pico.
#
# Reemplaza al main.py del bridge mientras debuggeamos. Cada 1 segundo
# imprime cuantos bytes leyó del UART0 y un dump hex del primer chunk.
# Tambien intenta varios baudrates por si la velocidad esta mal.
#
# Uso (host):
#   PYTHONPATH=.venv-tools python3 -m mpremote connect /dev/ttyACM0 cp pico/uart_debug.py :main.py
#   reset y escuchar con `cat /dev/ttyACM0`

import sys
import time
import micropython
from machine import UART, Pin

micropython.kbd_intr(-1)

# Probamos 115200 primero (lo que esperamos del GBA en modo UART SIO)
print("=== UART DEBUG ===")
print("ventana de rescate 2s (Ctrl-C para REPL)")
for _ in range(20):
    time.sleep_ms(100)
print("ventana cerrada, kbd_intr desactivado")

BAUDRATES = [115200, 57600, 38400, 9600]
b_idx = 0

uart = UART(0, baudrate=BAUDRATES[b_idx], bits=8, parity=None, stop=1,
            tx=Pin(0), rx=Pin(1), timeout=0, rxbuf=2048)
print("escuchando UART0 a", BAUDRATES[b_idx], "baud")

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
            print("baud", BAUDRATES[b_idx], ": 0 bytes (silencio)")
            # tras 5s de silencio, probar siguiente baudrate
            try:
                uart_silence_count
            except NameError:
                uart_silence_count = 0
            uart_silence_count += 1
            if uart_silence_count >= 5:
                uart_silence_count = 0
                b_idx = (b_idx + 1) % len(BAUDRATES)
                print("=== rotando a baud", BAUDRATES[b_idx])
                uart.deinit()
                uart = UART(0, baudrate=BAUDRATES[b_idx], bits=8, parity=None,
                            stop=1, tx=Pin(0), rx=Pin(1), timeout=0, rxbuf=2048)
