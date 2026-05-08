# Bridge USB-CDC <-> UART0 para Raspberry Pi Pico (RP2040).
#
# Reemplaza al bridge antiguo basado en Raspberry Pi 3/4 + /dev/ttyS0.
# El Pico es 3.3V CMOS nativo en GP0/GP1, mismo nivel eléctrico que el SIO
# del GBA en modo UART, por lo que NO hace falta level shifter.
#
# Cableado (ver docs/PICO_BRIDGE.md):
#   GBA pin 2 (SO, rojo)     -> Pico GP1 (UART0 RX)
#   GBA pin 3 (SI, naranja)  -> Pico GP0 (UART0 TX)
#   GBA pin 6 (GND, azul)    -> Pico GND
#   GBA pin 1 (VDD)          -> NC (el Pico se alimenta por USB)
#
# Instalación:
#   1. flashea MicroPython: descarga la UF2 oficial desde
#      https://micropython.org/download/RPI_PICO/ y arrástrala al
#      drive RPI-RP2 que aparece al pulsar BOOTSEL.
#   2. copia este archivo como `main.py` en el sistema de ficheros del
#      Pico (con `mpremote cp pico/main.py :main.py` o Thonny).
#   3. desconecta y reconecta USB. Aparece como /dev/ttyACM0 (Linux) o
#      COMx (Windows). El bridge arranca solo en cada boot.
#
# VENTANA DE RESCATE (importante):
#   Durante los primeros 2 segundos tras boot, NO se desactiva Ctrl-C.
#   Si pulsas Ctrl-C en `mpremote repl` durante esa ventana, el script
#   se interrumpe y caes a la REPL para poder reflashear sin necesidad
#   de modo BOOTSEL. Pasados los 2s, kbd_intr(-1) hace al bridge inmune
#   a bytes binarios (incluido 0x03) en stdin.
#
# Validación rápida (sin GBA, lazo TX-RX puenteando GP0 con GP1):
#   python3 -c "import serial; s=serial.Serial('/dev/ttyACM0',115200); \
#                s.write(b'ping\\n'); print(s.read(5))"

import sys
import select
import time
import micropython
from machine import UART, Pin

# === Ventana de rescate de 2 segundos (Ctrl-C aun mata el script) ========
print("gba-signer bridge: rescue window 2s (press Ctrl-C in REPL to abort)")
for i in range(20):
    time.sleep_ms(100)
print("gba-signer bridge: starting bridge mode")

# === Bridge real ==========================================================
# CRITICAL: ahora si, desactiva el interceptor de Ctrl-C en stdin. Sin esto
# cualquier byte 0x03 que pase por USB-CDC mata el bucle. Vamos a transportar
# RLP binario, asi que es mandatorio.
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
        # GBA -> PC: drena UART y vuelca a USB-CDC.
        if uart.any():
            chunk = uart.read(64)
            if chunk:
                sys.stdout.buffer.write(chunk)

        # PC -> GBA: lee de USB-CDC (no bloqueante via poll) y empuja al UART.
        # Importante: usar read1() para no bloquear si poll() miente sobre la
        # cantidad de bytes disponibles. read() bloquea esperando los N bytes.
        if poller.poll(0):
            try:
                b = sys.stdin.buffer.read1(64)
            except AttributeError:
                # micropython sin read1: cae a read(1) (un byte cada vez)
                b = sys.stdin.buffer.read(1)
            if b:
                uart.write(b)
except Exception as e:
    sys.stderr.write("bridge crash: %r\n" % e)
    time.sleep_ms(200)
    import machine
    machine.reset()
