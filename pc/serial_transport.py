"""Transport sobre /dev/ttyS0 (UART hardware) — usado en Raspberry Pi.

Cableado GBA link cable ↔ Pi GPIO:
    GBA SO  → Pi GPIO15 (RXD0, pin 10)
    GBA SI  ← Pi GPIO14 (TXD0, pin 8)
    GBA SC  ← (no usado en modo UART asíncrono)
    GBA SD  → (idem)
    GBA GND ↔ Pi GND (pin 6, 9, etc.)

NO conectar Vcc del cable a la Pi: el GBA se alimenta de su propia
batería. Si compartes GND y nada más, los niveles 3.3V LVTTL del GBA son
compatibles directamente con los pines GPIO 3.3V de la Pi (no hace falta
level shifter para Pi 1/2/3/4/5).

Habilitar UART en la Pi:
    sudo raspi-config → Interface → Serial → no consola login, sí HW
    (o en /boot/config.txt: enable_uart=1, dtoverlay=disable-bt en Pi3+)
"""
from __future__ import annotations

import time

import serial

from protocol import GbaTransport


class SerialTransport(GbaTransport):
    """Transporte sobre /dev/ttyACM0 (Pico USB-CDC bridge → UART al GBA).

    Historia:
      v1: el SIO del GBA en modo UART tiene un FIFO RX de SOLO 4 bytes y
          `uart_recv_byte_timeout` original solo lo drenaba una vez por
          VBlank (~16 ms = 60 B/s). Con bursts a 115200 baud el FIFO
          desbordaba y perdíamos bytes silenciosamente.
      v2: el firmware del GBA ahora usa busy-spin en `uart_recv_byte_busy`
          dentro de `protocol_recv_tx_rlp`, drenando el FIFO al ritmo del
          CPU (~MB/s). Ya no necesitamos throttle agresivo del host.

    Mantengo un throttle MUY ligero (32 B / 0.5 ms = ~60 KB/s) por dos
    motivos defensivos:
      - el bridge MicroPython en el Pico hace polling y un burst gigante
        podria saturar el buffer del UART TX del Pico (512 B).
      - le da al GBA tiempo entre chunks para procesar interrupts (por
        ejemplo si quisieramos meter VBlank cooperativo en el futuro).
    Si el firmware del GBA mejora aun mas, se puede subir/quitar."""

    # El Pico USB-CDC se resetea cuando se abre el puerto si DTR/RTS hace
    # toggle (comportamiento por defecto de pyserial en algunos drivers de
    # Linux). Tras el reset el bridge MicroPython tarda ~2.5s en arrancar
    # (rescue window 2s + boot). Si empezamos a leer antes, perdemos los
    # READYs del GBA y todo desincroniza. Por eso esperamos al inicio.
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
        # dtr/rts a False *antes* de open() reduce el toggle de algunos
        # drivers, pero no lo elimina completo. Por eso ademas hay
        # boot_settle_s.
        self.ser.dtr = False
        self.ser.rts = False
        self.ser.timeout = 30.0
        self.ser.open()

        self.chunk_size = chunk_size
        self.chunk_delay_s = chunk_delay_s

        # Espera a que el Pico termine de arrancar tras el (posible) reset
        # del open(). Durante este tiempo los bytes que el bridge propaga
        # son los primeros READY del GBA tras estar conectado de nuevo.
        settle = boot_settle_s if boot_settle_s is not None else self.BOOT_SETTLE_S
        if settle > 0:
            time.sleep(settle)

        # Drena cualquier byte residual (READY pulses acumulados durante el
        # boot del Pico, restos de sesiones previas, etc.). El siguiente
        # read() tendra un READY "fresco".
        self._drain()

    def _drain(self, settle_s: float = 0.2) -> None:
        """Lee bytes hasta que no llegue nada en `settle_s` segundos."""
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
                raise TimeoutError(f"esperando {n} bytes, recibí {len(out)}")
        return bytes(out)

    def write(self, data: bytes) -> None:
        # Trocea para no desbordar el FIFO RX del GBA (4 bytes).
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
