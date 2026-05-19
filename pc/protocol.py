"""Handshake protocol definition for Coldpakku (v7).

After ACK the host sends one of these opcodes:
  - PROTO_TX_RLP        (0xCD): RLP-serialized Ethereum tx
  - PROTO_TX_RLP_META   (0xD2): same + host-supplied metadata TLV
  - PROTO_GET_ADDRESS   (0xC0): read the active address, no signing
  - PROTO_PERSONAL_SIGN (0xD0): EIP-191 personal_sign over a UTF-8 msg
  - PROTO_TYPED_DATA    (0xD1): EIP-712 (host pre-computes domainSep +
                                msgHash; v7 also appends a TLV tree the
                                GBA can verify on-device when the user
                                presses L+R on the confirm screen)
  - PROTO_HEARTBEAT     (0xC4): ~5 s tick to keep the 'link:' indicator alive
  - PROTO_CONNECT_REQUEST (0xC5): dApp eth_requestAccounts approval
  - PROTO_GET_POLICY    (0xC2): read the chain currently locked

For tx the GBA parses the RLP on-device. For personal_sign it hashes
the message with the EIP-191 prefix. For typed_data the GBA trusts the
host-precomputed hashes by default but, with the v7 tree, can re-derive
them itself and verify byte-for-byte before signing.

Identical over the mGBA TCP socket and over the Pico's /dev/ttyACM0.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Optional

PROTO_READY          = 0xAA
PROTO_ACK            = 0xBB
PROTO_TX_RLP         = 0xCD
PROTO_DONE           = 0xCC
PROTO_SIGSTART       = 0xCE
PROTO_TXRESULT       = 0xCF
PROTO_CANCEL         = 0xFF

# v4
PROTO_GET_ADDRESS    = 0xC0
PROTO_ADDRSTART      = 0xC1
PROTO_PERSONAL_SIGN  = 0xD0
PROTO_TYPED_DATA     = 0xD1

# v6: tx + informational metadata (origin, contract name, token info)
PROTO_TX_RLP_META    = 0xD2

# TLV types inside the meta block. Keep in sync with
# src/link/protocol.h (META_TYPE_*).
META_TYPE_ORIGIN      = 0x01
META_TYPE_TO_NAME     = 0x02
META_TYPE_TO_SYMBOL   = 0x03
META_TYPE_TO_DECIMALS = 0x04

META_ORIGIN_MAX      = 96
META_NAME_MAX        = 32
META_SYMBOL_MAX      = 16
PROTO_TX_META_MAX    = 256

PROTO_TX_RLP_MAX        = 4096
PROTO_PERSONAL_MSG_MAX  = 4096
PROTO_TYPED_TEXT_MAX    = 4096
# v7: optional EIP-712 TLV tree appended to PROTO_TYPED_DATA. 0 = blind only.
PROTO_TYPED_TREE_MAX    = 8192

# v7: caps mirrored in src/crypto/eip712.h and docs/PROTOCOL.md.
EIP712_MAX_TYPES             = 32
EIP712_MAX_FIELDS_PER_TYPE   = 32
EIP712_MAX_NAME_LEN          = 32
EIP712_MAX_TYPE_LEN          = 40
EIP712_MAX_STRING_LEN        = 1024

# Status bytes for PROTO_TXRESULT
TXRESULT_BROADCAST_OK   = 0x00
TXRESULT_BROADCAST_ERR  = 0x01
TXRESULT_NO_BROADCAST   = 0x02

TXRESULT_ERRMSG_MAX = 64

SIG_V_SENTINEL = 0xFE


@dataclass
class TxMeta:
    """Informational metadata that travels with the tx in PROTO_TX_RLP_META.

    Every field is optional. Strings are sanitized to visible ASCII on
    serialization (any non-ASCII is replaced by '?'). The GBA shows them
    as "host says X" — they are UX hints, not crypto-verifiable.
    """
    origin: Optional[str] = None        # "app.uniswap.org", "pancakeswap.finance/swap"
    to_name: Optional[str] = None       # "WETH9", "Uniswap V3 Router"
    to_symbol: Optional[str] = None     # "WETH", "USDC", "WBNB"
    to_decimals: Optional[int] = None   # 0..77

    @staticmethod
    def _sanitize(s: str, max_len: int) -> bytes:
        """Visible ASCII (0x20..0x7E); replace anything else with '?'. Truncate."""
        out = bytearray()
        for ch in s[:max_len]:
            o = ord(ch)
            out.append(o if 0x20 <= o < 0x7F else ord('?'))
        return bytes(out)

    def encode_tlv(self) -> bytes:
        """Encode the present fields as TLV (type:1 + len:1 + value)."""
        out = bytearray()
        if self.origin is not None:
            v = self._sanitize(self.origin, META_ORIGIN_MAX)
            out.append(META_TYPE_ORIGIN); out.append(len(v)); out += v
        if self.to_name is not None:
            v = self._sanitize(self.to_name, META_NAME_MAX)
            out.append(META_TYPE_TO_NAME); out.append(len(v)); out += v
        if self.to_symbol is not None:
            v = self._sanitize(self.to_symbol, META_SYMBOL_MAX)
            out.append(META_TYPE_TO_SYMBOL); out.append(len(v)); out += v
        if self.to_decimals is not None:
            d = int(self.to_decimals)
            if 0 <= d <= 77:
                out.append(META_TYPE_TO_DECIMALS); out.append(1); out.append(d)
        if len(out) > PROTO_TX_META_MAX:
            raise ValueError(f"meta TLV size {len(out)} > PROTO_TX_META_MAX={PROTO_TX_META_MAX}")
        return bytes(out)

    def is_empty(self) -> bool:
        return (self.origin is None and self.to_name is None
                and self.to_symbol is None and self.to_decimals is None)


@dataclass
class RlpTx:
    """Transaction already serialized as RLP (envelope included for EIP-1559).

    If `meta` is present and non-empty, the PROTO_TX_RLP_META opcode
    (0xD2) is used with a trailing meta TLV block. Otherwise the classic
    PROTO_TX_RLP opcode (0xCD) without meta — compatible with older ROMs.
    """

    rlp: bytes
    meta: Optional[TxMeta] = None

    def serialize(self) -> bytes:
        if len(self.rlp) == 0 or len(self.rlp) > PROTO_TX_RLP_MAX:
            raise ValueError(f"rlp size out of range: {len(self.rlp)}")
        out = bytearray()
        if self.meta is not None and not self.meta.is_empty():
            tlv = self.meta.encode_tlv()
            out.append(PROTO_TX_RLP_META)
            out += len(self.rlp).to_bytes(4, "big")
            out += self.rlp
            out += len(tlv).to_bytes(2, "big")
            out += tlv
        else:
            out.append(PROTO_TX_RLP)
            out += len(self.rlp).to_bytes(4, "big")
            out += self.rlp
        return bytes(out)


class GbaTransport:
    """Abstract interface. See MgbaSocketTransport / SerialTransport."""

    def read(self, n: int, timeout_s: float = 30.0) -> bytes: ...
    def write(self, data: bytes) -> None: ...
    def close(self) -> None: ...


def perform_signing(
    transport: GbaTransport,
    tx: RlpTx,
    timeout_s: float = 60.0,
) -> Optional[bytes]:
    """Run the complete handshake. Returns the 65B signature, or None if
    the user cancelled on the GBA.

    Flow:
      GBA -> READY (0xAA)            <- extra READYs are discarded
      PC  -> ACK   (0xBB)
      PC  -> TX_RLP opcode + len_be(4) + rlp_bytes
      GBA -> SIGSTART (0xCE) + 65B signature   or   CANCEL (0xFF)
      GBA -> DONE  (0xCC)

    The GBA pulses READY every 0.5s while it waits, so when the host
    reads the first READY there may be additional READYs in transit.
    We drain them while looking for the SIGSTART (or CANCEL) byte.
    """

    # 1) Read the first READY (drain any pending READYs knowing it must
    #    be 0xAA).
    deadline_first = timeout_s
    b = transport.read(1, deadline_first)
    if b[0] != PROTO_READY:
        raise RuntimeError(f"expected READY (0xAA), got {b[0]:#04x}")

    # 2) ACK + payload. We need a small gap between the ACK and the
    #    payload so the GBA has time to process the ACK and enter
    #    `protocol_recv_tx_rlp`. Without the gap the first payload bytes
    #    are lost (the sign_loop keeps running UI frames when they
    #    arrive and the 4-byte FIFO overflows).
    transport.write(bytes([PROTO_ACK]))
    time.sleep(0.05)
    transport.write(tx.serialize())

    # 3) Discard any residual READY (0xAA) from the pulse cycle until we
    #    see the SIGSTART (0xCE) or CANCEL (0xFF) marker. We cap the
    #    drain to avoid looping forever if something is off.
    max_drain = 32
    marker = None
    for _ in range(max_drain):
        b = transport.read(1, timeout_s)
        if b[0] == PROTO_READY:
            continue
        marker = b[0]
        break
    if marker is None:
        raise RuntimeError("flooded with READYs: no SIGSTART or CANCEL arrived")
    if marker == PROTO_CANCEL:
        _ = transport.read(1, timeout_s)  # DONE
        return None
    if marker != PROTO_SIGSTART:
        raise RuntimeError(f"expected SIGSTART (0xCE) or CANCEL, got {marker:#04x}")

    # 4) 65B signature + DONE
    sig = transport.read(65, timeout_s)
    done = transport.read(1, timeout_s)
    if done[0] != PROTO_DONE:
        raise RuntimeError(f"expected DONE (0xCC), got {done[0]:#04x}")
    return sig


def send_tx_result(
    transport: GbaTransport,
    status: int,
    txhash: Optional[bytes] = None,
    errmsg: Optional[str] = None,
) -> None:
    """Send PROTO_TXRESULT to the GBA after attempting to broadcast.

    The GBA paints the "TX RESULT" screen and waits for A to return to
    the awaiting-transaction screen. If you don't call this, the GBA
    will time out cooperatively (~30s) and return on its own
    (compat with older hosts).

    Wire layout:
      0xCF (opcode) | 1B status | payload
      payload =
        if status == 0x00 BROADCAST_OK   -> 32B txhash
        if status == 0x02 NO_BROADCAST   -> 32B txhash
        if status == 0x01 BROADCAST_ERR  -> 1B len + len UTF-8 bytes

    Pauses briefly before sending so the GBA can finish painting the
    "BROADCASTING..." screen and enter the polling loop without bytes
    piling up in its FIFO (same reason as the ACK->RLP gap in
    perform_signing).
    """
    payload = bytearray()
    payload.append(status & 0xFF)
    if status in (TXRESULT_BROADCAST_OK, TXRESULT_NO_BROADCAST):
        if txhash is None or len(txhash) != 32:
            raise ValueError("OK status requires a 32-byte txhash")
        payload += txhash
    elif status == TXRESULT_BROADCAST_ERR:
        msg = (errmsg or "").encode("utf-8")[:TXRESULT_ERRMSG_MAX]
        payload.append(len(msg))
        payload += msg
    else:
        raise ValueError(f"unknown status: {status:#04x}")

    # Pause before the opcode: the GBA has just painted "BROADCASTING..."
    # and needs a few frames to enter the polling loop. Without this the
    # bytes arrive before the GBA polls the FIFO.
    time.sleep(0.05)

    # Send the opcode ALONE. The GBA polls the FIFO once per VBlank
    # (~16ms); in that window only 1 byte fits without risking an
    # overflow of the 4-byte FIFO. After detecting the opcode the GBA
    # enters busy-spin and can drain at CPU speed.
    transport.write(bytes([PROTO_TXRESULT]))
    time.sleep(0.025)

    # Now the rest: status + payload. The GBA is in busy-spin and reads
    # at CPU pace (not UART), so a burst is fine.
    transport.write(bytes(payload))


# ============================================================================
# v4 - new flows: get_address / personal_sign / typed_data
# ============================================================================


def _wait_first_ready(transport: GbaTransport, timeout_s: float) -> None:
    """Read bytes until we find the first READY (0xAA). The GBA pulses
    every 0.5s while waiting, so we usually catch one almost
    immediately. Raises if anything else arrives."""
    b = transport.read(1, timeout_s)
    if b[0] != PROTO_READY:
        raise RuntimeError(f"expected READY (0xAA), got {b[0]:#04x}")


def _drain_until(transport: GbaTransport, markers: bytes, timeout_s: float) -> int:
    """Read bytes, discarding READYs (0xAA), until one of the allowed
    markers shows up. Returns the marker. Raises after 32 bytes."""
    for _ in range(32):
        b = transport.read(1, timeout_s)
        if b[0] == PROTO_READY:
            continue
        if b[0] in markers:
            return b[0]
        raise RuntimeError(
            f"unexpected marker {b[0]:#04x}; expected one of {markers!r}"
        )
    raise RuntimeError("flooded with READYs: no valid marker arrived")


def perform_get_address(transport: GbaTransport, timeout_s: float = 30.0) -> bytes:
    """Ask the GBA for its address without signing anything. Returns
    20 raw bytes.

    Flow:
      GBA -> READY
      PC  -> ACK + PROTO_GET_ADDRESS
      GBA -> ADDRSTART (0xC1) + 20B address
      GBA -> DONE (0xCC)
    """
    _wait_first_ready(transport, timeout_s)
    transport.write(bytes([PROTO_ACK]))
    time.sleep(0.05)
    transport.write(bytes([PROTO_GET_ADDRESS]))
    marker = _drain_until(transport, bytes([PROTO_ADDRSTART, PROTO_CANCEL]), timeout_s)
    if marker == PROTO_CANCEL:
        _ = transport.read(1, timeout_s)  # DONE
        raise RuntimeError("GBA cancelled get_address")
    addr = transport.read(20, timeout_s)
    done = transport.read(1, timeout_s)
    if done[0] != PROTO_DONE:
        raise RuntimeError(f"expected DONE after address, got {done[0]:#04x}")
    return bytes(addr)


def perform_personal_sign(
    transport: GbaTransport,
    msg: bytes,
    timeout_s: float = 60.0,
) -> Optional[bytes]:
    """Ask the GBA to sign `msg` according to EIP-191 (personal_sign).

    The GBA prepends "\\x19Ethereum Signed Message:\\n<len>" and hashes
    with keccak. It shows the message on screen and prompts A/B.
    Returns the 65B signature (with v=0xFE sentinel; caller must run
    recovery to obtain the real v), or None if the user cancelled.

    Flow:
      GBA -> READY
      PC  -> ACK + PROTO_PERSONAL_SIGN + 4B len + msg
      GBA -> SIGSTART + 65B sig (or CANCEL)
      GBA -> DONE
    """
    if len(msg) > PROTO_PERSONAL_MSG_MAX:
        raise ValueError(f"msg of {len(msg)} bytes exceeds PROTO_PERSONAL_MSG_MAX")

    _wait_first_ready(transport, timeout_s)
    transport.write(bytes([PROTO_ACK]))
    time.sleep(0.05)

    payload = bytearray()
    payload.append(PROTO_PERSONAL_SIGN)
    payload += len(msg).to_bytes(4, "big")
    payload += msg
    transport.write(bytes(payload))

    marker = _drain_until(transport, bytes([PROTO_SIGSTART, PROTO_CANCEL]), timeout_s)
    if marker == PROTO_CANCEL:
        _ = transport.read(1, timeout_s)  # DONE
        return None
    sig = transport.read(65, timeout_s)
    done = transport.read(1, timeout_s)
    if done[0] != PROTO_DONE:
        raise RuntimeError(f"expected DONE, got {done[0]:#04x}")
    return bytes(sig)


def perform_typed_data(
    transport: GbaTransport,
    domain_separator: bytes,
    message_hash: bytes,
    human_text: bytes,
    tree_bytes: bytes = b"",
    timeout_s: float = 60.0,
) -> Optional[bytes]:
    """Ask the GBA to sign EIP-712 with the pre-computed hashes.

    The GBA computes keccak256(0x1901 || domainSeparator || messageHash)
    by default, shows `human_text` plus the truncated hex hashes for
    manual verification, and asks A/B.

    v7 adds an optional `tree_bytes` payload (the TLV serialization of
    the TypedData; see docs/PROTOCOL.md). When non-empty the cartridge
    lets the user press L+R on the confirm screen to parse the tree on-
    device, re-derive `domainSeparator` and `messageHash`, and verify
    them against the host's. Pass b"" to keep the legacy blind-only flow.

    Returns the 65B signature with v=0xFE sentinel (caller handles
    recovery), or None if the user cancelled.

    Flow:
      GBA -> READY
      PC  -> ACK + PROTO_TYPED_DATA + 32B ds + 32B mh
           + 4B textlen + text
           + 2B treelen + tree
      GBA -> SIGSTART + 65B sig (or CANCEL)
      GBA -> DONE
    """
    if len(domain_separator) != 32 or len(message_hash) != 32:
        raise ValueError("domain_separator and message_hash must be 32 bytes")
    if len(human_text) > PROTO_TYPED_TEXT_MAX:
        raise ValueError(f"human_text of {len(human_text)} bytes exceeds PROTO_TYPED_TEXT_MAX")
    if len(tree_bytes) > PROTO_TYPED_TREE_MAX:
        raise ValueError(f"tree_bytes of {len(tree_bytes)} bytes exceeds PROTO_TYPED_TREE_MAX")
    if len(tree_bytes) > 0xFFFF:
        raise ValueError("tree_bytes must fit in the 2B wire length field")

    _wait_first_ready(transport, timeout_s)
    transport.write(bytes([PROTO_ACK]))
    time.sleep(0.05)

    payload = bytearray()
    payload.append(PROTO_TYPED_DATA)
    payload += domain_separator
    payload += message_hash
    payload += len(human_text).to_bytes(4, "big")
    payload += human_text
    payload += len(tree_bytes).to_bytes(2, "big")
    payload += tree_bytes
    transport.write(bytes(payload))

    marker = _drain_until(transport, bytes([PROTO_SIGSTART, PROTO_CANCEL]), timeout_s)
    if marker == PROTO_CANCEL:
        _ = transport.read(1, timeout_s)  # DONE
        return None
    sig = transport.read(65, timeout_s)
    done = transport.read(1, timeout_s)
    if done[0] != PROTO_DONE:
        raise RuntimeError(f"expected DONE, got {done[0]:#04x}")
    return bytes(sig)


# ============================================================================
# v7: EIP-712 TLV serialization (mirror of extension/src/lib/eip712.ts
# :serializeTypedDataTLV). Used by tests and host tools to exercise the
# on-device parser without going through the browser extension. Wire
# layout is the one documented in docs/PROTOCOL.md.
# ============================================================================

def _eip712_base_type(t: str) -> str:
    i = t.find("[")
    return t if i < 0 else t[:i]


def _hex_or_bytes(v) -> bytes:
    if isinstance(v, (bytes, bytearray, memoryview)):
        return bytes(v)
    if isinstance(v, str):
        s = v[2:] if v[:2] in ("0x", "0X") else v
        return bytes.fromhex(s)
    raise TypeError(f"expected hex string or bytes, got {type(v).__name__}")


def serialize_typed_data_tlv(td: dict) -> bytes:
    """Serialize a TypedData dict (eth_account / EIP-712 style) to the v7
    TLV format. Caps mirrored in src/crypto/eip712.h.
    """
    types = td.get("types") or {}
    if "EIP712Domain" not in types:
        raise ValueError("missing EIP712Domain in types")
    primary = td.get("primaryType")
    if not primary or primary not in types:
        raise ValueError(f"unknown primaryType {primary!r}")

    # DFS collect referenced struct types in deterministic discovery order.
    order: list[str] = []
    seen: set[str] = set()

    def collect(name: str) -> None:
        if name in seen or name not in types:
            return
        seen.add(name)
        order.append(name)
        for f in types[name]:
            collect(_eip712_base_type(f["type"]))

    collect("EIP712Domain")
    collect(primary)

    if len(order) > EIP712_MAX_TYPES:
        raise ValueError(f"too many types {len(order)} > {EIP712_MAX_TYPES}")
    if order[0] != "EIP712Domain":
        raise ValueError("internal: EIP712Domain not at index 0")
    primary_idx = order.index(primary)

    out = bytearray()

    def push_u8(v: int) -> None:
        out.append(v & 0xFF)

    def push_u32_be(v: int) -> None:
        out.extend(int(v).to_bytes(4, "big"))

    def push_ascii(s: str, max_len: int, label: str) -> None:
        u = s.encode("utf-8")
        if not u:
            raise ValueError(f"empty {label}")
        if len(u) > max_len:
            raise ValueError(f"{label} {s!r} length {len(u)} > {max_len}")
        push_u8(len(u))
        out.extend(u)

    # Type table
    push_u8(len(order))
    for name in order:
        push_ascii(name, EIP712_MAX_NAME_LEN, "type name")
        fields = types[name]
        if not fields or len(fields) > EIP712_MAX_FIELDS_PER_TYPE:
            raise ValueError(f"type {name} has {len(fields)} fields")
        push_u8(len(fields))
        for f in fields:
            push_ascii(f["name"], EIP712_MAX_NAME_LEN, f"field name in {name}")
            push_ascii(f["type"], EIP712_MAX_TYPE_LEN, f"field type in {name}")

    push_u8(primary_idx)

    # Value sections (depth-first, same order as the type table reads).
    def write_value(type_str: str, v, parent: str, field: str) -> None:
        if type_str.endswith("]"):
            inner = type_str[: type_str.rfind("[")]
            if not isinstance(v, (list, tuple)):
                raise ValueError(f"array field {parent}.{field} is not iterable")
            push_u32_be(len(v))
            for item in v:
                write_value(inner, item, parent, field)
            return
        if type_str in types:
            write_struct(type_str, v)
            return
        if type_str == "string":
            u = str(v if v is not None else "").encode("utf-8")
            if len(u) > EIP712_MAX_STRING_LEN:
                raise ValueError(f"string {parent}.{field} too long")
            push_u32_be(len(u))
            out.extend(u)
            return
        if type_str == "bytes":
            u = _hex_or_bytes(v)
            if len(u) > EIP712_MAX_STRING_LEN:
                raise ValueError(f"bytes {parent}.{field} too long")
            push_u32_be(len(u))
            out.extend(u)
            return
        if type_str == "address":
            u = _hex_or_bytes(v)
            if len(u) != 20:
                raise ValueError(f"address {parent}.{field}: got {len(u)} bytes, want 20")
            out.extend(u)
            return
        if type_str == "bool":
            push_u8(1 if v else 0)
            return
        if type_str.startswith("uint"):
            bits = int(type_str[4:] or "256")
            if bits < 8 or bits > 256 or bits % 8 != 0:
                raise ValueError(f"bad uint width in {type_str}")
            n_bytes = bits // 8
            n = int(v)
            if n < 0 or n >= (1 << bits):
                raise ValueError(f"uint{bits} overflow at {parent}.{field}: {n}")
            out.extend(n.to_bytes(n_bytes, "big"))
            return
        if type_str.startswith("int"):
            bits = int(type_str[3:] or "256")
            if bits < 8 or bits > 256 or bits % 8 != 0:
                raise ValueError(f"bad int width in {type_str}")
            n_bytes = bits // 8
            mask = (1 << bits) - 1
            n = int(v) & mask
            out.extend(n.to_bytes(n_bytes, "big"))
            return
        if type_str.startswith("bytes"):
            n_bytes = int(type_str[5:])
            if n_bytes < 1 or n_bytes > 32:
                raise ValueError(f"bad bytesN in {type_str}")
            u = _hex_or_bytes(v)
            if len(u) != n_bytes:
                raise ValueError(
                    f"{type_str} {parent}.{field}: got {len(u)} bytes, want {n_bytes}"
                )
            out.extend(u)
            return
        raise ValueError(f"unsupported EIP-712 type {type_str!r} at {parent}.{field}")

    def write_struct(name: str, obj) -> None:
        if obj is None:
            obj = {}
        for f in types[name]:
            value = obj[f["name"]] if isinstance(obj, dict) else getattr(obj, f["name"])
            write_value(f["type"], value, name, f["name"])

    write_struct("EIP712Domain", td.get("domain", {}))
    write_struct(primary, td.get("message", {}))
    return bytes(out)
