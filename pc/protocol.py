"""Definición del protocolo handshake con el GBA Signer (v2 — RLP).

El host envía la transacción RLP-serializada cruda. La GBA la parsea, calcula
keccak256 internamente y firma. Esto evita que el bridge pueda mostrarte un
to/value bonito en pantalla y firmar otro hash.

Idéntico tanto sobre socket TCP de mGBA como sobre /dev/ttyACM0 del Pico.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Optional

PROTO_READY    = 0xAA
PROTO_ACK      = 0xBB
PROTO_TX_RLP   = 0xCD
PROTO_DONE     = 0xCC
PROTO_SIGSTART = 0xCE
PROTO_TXRESULT = 0xCF
PROTO_CANCEL   = 0xFF

PROTO_TX_RLP_MAX = 4096

# Status bytes para PROTO_TXRESULT
TXRESULT_BROADCAST_OK   = 0x00
TXRESULT_BROADCAST_ERR  = 0x01
TXRESULT_NO_BROADCAST   = 0x02

TXRESULT_ERRMSG_MAX = 64

SIG_V_SENTINEL = 0xFE


@dataclass
class RlpTx:
    """Transacción ya serializada en RLP (envelope incluido para EIP-1559)."""

    rlp: bytes

    def serialize(self) -> bytes:
        if len(self.rlp) == 0 or len(self.rlp) > PROTO_TX_RLP_MAX:
            raise ValueError(f"rlp size out of range: {len(self.rlp)}")
        out = bytearray()
        out.append(PROTO_TX_RLP)
        out += len(self.rlp).to_bytes(4, "big")
        out += self.rlp
        return bytes(out)


class GbaTransport:
    """Interfaz abstracta. Ver MgbaSocketTransport / SerialTransport."""

    def read(self, n: int, timeout_s: float = 30.0) -> bytes: ...
    def write(self, data: bytes) -> None: ...
    def close(self) -> None: ...


def perform_signing(
    transport: GbaTransport,
    tx: RlpTx,
    timeout_s: float = 60.0,
) -> Optional[bytes]:
    """Ejecuta el handshake completo. Devuelve la firma 65B o None si el
    usuario canceló en el GBA.

    Flujo:
      GBA -> READY (0xAA)            ← se descartan READYs adicionales
      PC  -> ACK   (0xBB)
      PC  -> TX_RLP opcode + len_be(4) + rlp_bytes
      GBA -> SIGSTART (0xCE) + 65B firma   o   CANCEL (0xFF)
      GBA -> DONE  (0xCC)

    El GBA pulsa READY cada 0.5s mientras espera, asi que cuando el host
    lee el primer READY puede haber otros READY adicionales en transit.
    Esos los drenamos buscando el byte SIGSTART (o CANCEL).
    """

    # 1) lee el primer READY (drena cualquier READY pendiente buscando uno
    #    a sabiendas que es 0xAA).
    deadline_first = timeout_s
    b = transport.read(1, deadline_first)
    if b[0] != PROTO_READY:
        raise RuntimeError(f"esperaba READY (0xAA), recibi {b[0]:#04x}")

    # 2) ACK + payload. Hace falta un pequeño gap entre el ACK y el inicio
    #    del payload para darle al GBA tiempo a procesar el ACK y entrar en
    #    `protocol_recv_tx_rlp`. Sin gap, los primeros bytes del payload se
    #    le pierden (el sign_loop sigue ejecutando frames de UI cuando llegan
    #    y el FIFO de 4 bytes desborda).
    transport.write(bytes([PROTO_ACK]))
    time.sleep(0.05)
    transport.write(tx.serialize())

    # 3) descarta cualquier READY (0xAA) residual del pulse cycle hasta
    #    encontrar el marker SIGSTART (0xCE) o CANCEL (0xFF). Hay un cap
    #    para evitar quedarnos buscando para siempre si algo va mal.
    max_drain = 32
    marker = None
    for _ in range(max_drain):
        b = transport.read(1, timeout_s)
        if b[0] == PROTO_READY:
            continue
        marker = b[0]
        break
    if marker is None:
        raise RuntimeError("flooded de READY: no llego SIGSTART ni CANCEL")
    if marker == PROTO_CANCEL:
        _ = transport.read(1, timeout_s)  # DONE
        return None
    if marker != PROTO_SIGSTART:
        raise RuntimeError(f"esperaba SIGSTART (0xCE) o CANCEL, recibi {marker:#04x}")

    # 4) firma 65B + DONE
    sig = transport.read(65, timeout_s)
    done = transport.read(1, timeout_s)
    if done[0] != PROTO_DONE:
        raise RuntimeError(f"esperaba DONE (0xCC), recibi {done[0]:#04x}")
    return sig


def send_tx_result(
    transport: GbaTransport,
    status: int,
    txhash: Optional[bytes] = None,
    errmsg: Optional[str] = None,
) -> None:
    """Envia PROTO_TXRESULT al GBA tras intentar broadcast.

    El GBA pintara la pantalla "TX RESULT" y esperara A para volver a
    awaiting transaction. Si no llamas a esta funcion, el GBA hara
    timeout cooperativo (~30s) y volvera solo (compat con hosts viejos).

    Layout en el wire:
      0xCF (opcode) | 1B status | payload
      payload =
        si status == 0x00 BROADCAST_OK   -> 32B txhash
        si status == 0x02 NO_BROADCAST   -> 32B txhash
        si status == 0x01 BROADCAST_ERR  -> 1B len + len bytes UTF-8

    Hace una pausa breve antes de enviar para que el GBA termine de
    pintar la pantalla "BROADCASTING..." y entre en el loop de polling
    sin que se le acumulen bytes en el FIFO (mismo motivo que el gap
    ACK->RLP en perform_signing).
    """
    payload = bytearray()
    payload.append(status & 0xFF)
    if status in (TXRESULT_BROADCAST_OK, TXRESULT_NO_BROADCAST):
        if txhash is None or len(txhash) != 32:
            raise ValueError("status OK requiere txhash de 32 bytes")
        payload += txhash
    elif status == TXRESULT_BROADCAST_ERR:
        msg = (errmsg or "").encode("utf-8")[:TXRESULT_ERRMSG_MAX]
        payload.append(len(msg))
        payload += msg
    else:
        raise ValueError(f"status desconocido: {status:#04x}")

    # Pausa antes del opcode: el GBA acaba de pintar la pantalla
    # "BROADCASTING..." y necesita unos frames para entrar en el loop de
    # polling. Sin esto los bytes llegan antes de que el GBA poleé el FIFO.
    time.sleep(0.05)

    # Mandamos el opcode SOLO. El GBA poleea el FIFO una vez por VBlank
    # (~16ms); en ese intervalo solo cabe 1 byte sin riesgo de overflow del
    # FIFO de 4 bytes. Tras detectar el opcode el GBA entra en busy-spin y
    # ya puede drenar a velocidad de CPU.
    transport.write(bytes([PROTO_TXRESULT]))
    time.sleep(0.025)

    # Ahora el resto: status + payload. El GBA esta en busy-spin y los
    # consume al ritmo del CPU, no del UART, asi que un burst esta bien.
    transport.write(bytes(payload))
