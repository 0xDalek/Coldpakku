"""Construye una transacción Ethereum, la firma con el GBA (que parsea el
RLP on-device) y la inyecta en la red vía RPC.

Uso típico (mGBA en localhost):
    python3 pc/metamask_inject.py \
        --rpc https://rpc.sepolia.org \
        --transport socket --port 12345 \
        --to 0x... --value-wei 100000000000000 [--data 0x...] \
        --address-from 0xYOUR_ADDRESS_HERE \
        [--no-broadcast]

Pico bridge (USB-CDC):
    python3 pc/metamask_inject.py \
        --rpc https://rpc.sepolia.org \
        --transport serial --serial-port /dev/ttyACM0 \
        --to 0x... --value-wei 100000000000000 \
        --address-from 0x...

Diferencia con la versión anterior: ya no calculamos el hash en host y se lo
mandamos a la GBA para que firme a ciegas. Ahora le mandamos los bytes RLP
crudos y la GBA decodifica + hashea + muestra los campos parseados antes de
firmar. El bridge ya no puede mentirle al usuario sobre to/value/data.
"""
from __future__ import annotations

import argparse
import sys

from eth_utils import keccak, to_canonical_address
from web3 import Web3

import rlp

from protocol import (
    RlpTx, perform_signing, send_tx_result,
    TXRESULT_BROADCAST_OK, TXRESULT_BROADCAST_ERR, TXRESULT_NO_BROADCAST,
)
from sig_recover import recover_address


def parse_int(s: str) -> int:
    return int(s, 0)


def build_unsigned_tx(w3: Web3, sender: str, to: str, value: int,
                      data: bytes, chainid: int) -> dict:
    nonce = w3.eth.get_transaction_count(sender)
    base_fee = w3.eth.gas_price
    return {
        "type": 2,
        "chainId": chainid,
        "nonce": nonce,
        "to": Web3.to_checksum_address(to),
        "value": value,
        "data": data,
        "maxFeePerGas": base_fee * 2,
        "maxPriorityFeePerGas": min(base_fee, 2_000_000_000),
        "gas": 21000 + 16 * len(data),
        "accessList": [],
    }


def encode_unsigned_eip1559(tx: dict) -> bytes:
    """Devuelve el blob que la GBA va a parsear y hashear:
    0x02 || rlp([chainId, nonce, maxPFee, maxFee, gas, to, value, data, []])
    """
    fields = [
        tx["chainId"],
        tx["nonce"],
        tx["maxPriorityFeePerGas"],
        tx["maxFeePerGas"],
        tx["gas"],
        bytes.fromhex(tx["to"][2:]),
        tx["value"],
        tx["data"],
        [],
    ]
    return b"\x02" + rlp.encode(fields)


def assemble_signed_rlp(tx: dict, sig_canonical: bytes) -> bytes:
    r = int.from_bytes(sig_canonical[:32], "big")
    s = int.from_bytes(sig_canonical[32:64], "big")
    v_legacy = sig_canonical[64]
    y_parity = v_legacy - 27
    fields = [
        tx["chainId"], tx["nonce"], tx["maxPriorityFeePerGas"], tx["maxFeePerGas"],
        tx["gas"], bytes.fromhex(tx["to"][2:]), tx["value"], tx["data"], [],
        y_parity, r, s,
    ]
    return b"\x02" + rlp.encode(fields)


def build_transport(args):
    if args.transport == "socket":
        from mgba_socket import MgbaSocketTransport
        return MgbaSocketTransport(args.host, args.port)
    if args.transport == "serial":
        from serial_transport import SerialTransport
        return SerialTransport(args.serial_port, baudrate=args.baud)
    raise SystemExit(f"transport desconocido: {args.transport}")


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--rpc", required=True)
    p.add_argument("--transport", choices=["socket", "serial"], default="socket")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=12345)
    p.add_argument("--serial-port", default="/dev/ttyACM0",
                   help="puerto serie del bridge Pico (default /dev/ttyACM0)")
    p.add_argument("--baud", type=int, default=115200)
    p.add_argument("--to", required=True)
    p.add_argument("--value-wei", required=True, type=parse_int)
    p.add_argument("--data", default="0x")
    p.add_argument("--address-from", required=True,
                   help="address esperada del firmante (la mostrada por el GBA)")
    p.add_argument("--no-broadcast", action="store_true",
                   help="firma pero no envía la tx; útil para auditoría")
    args = p.parse_args()

    w3 = Web3(Web3.HTTPProvider(args.rpc))
    chainid = w3.eth.chain_id
    print(f"[inject] RPC {args.rpc} chainid={chainid}")

    data = bytes.fromhex(args.data.removeprefix("0x"))
    tx = build_unsigned_tx(w3, args.address_from, args.to,
                           args.value_wei, data, chainid)
    print(f"[inject] tx unsigned: nonce={tx['nonce']} gas={tx['gas']} "
          f"maxFeePerGas={tx['maxFeePerGas']} value={tx['value']} to={tx['to']}")

    blob = encode_unsigned_eip1559(tx)
    h = keccak(blob)
    print(f"[inject] RLP unsigned ({len(blob)}B), expected hash = 0x{h.hex()}")

    payload = RlpTx(rlp=blob)

    print(f"[inject] conectando vía {args.transport}...")
    transport = build_transport(args)
    print(f"[inject] esperando READY, confirma la tx en el GBA...")
    sig = perform_signing(transport, payload)
    if sig is None:
        print("[inject] usuario CANCELO en el GBA")
        return 2

    print(f"[inject] firma cruda: {sig.hex()}")
    expected_addr = to_canonical_address(args.address_from)
    rec = recover_address(h, sig, expected_addr)
    if rec is None:
        print("[inject] ERROR: no se recupera la address esperada — firma invalida")
        return 3
    canonical, recid = rec
    print(f"[inject] firma canonical (v=27+{recid}): {canonical.hex()}")

    raw = assemble_signed_rlp(tx, canonical)
    print(f"[inject] tx serializada: 0x{raw.hex()[:80]}... ({len(raw)} bytes)")

    # Hash deterministico de la tx firmada (lo que veras en etherscan).
    # Lo computamos siempre, incluso en --no-broadcast, para que el GBA
    # pueda mostrar el hash en su pantalla TX RESULT.
    final_txhash = keccak(raw)

    if args.no_broadcast:
        print(f"[inject] --no-broadcast: deteniendose antes de enviar")
        print(f"[inject] hash que tendria si se enviara: 0x{final_txhash.hex()}")
        try:
            send_tx_result(transport, TXRESULT_NO_BROADCAST, txhash=final_txhash)
        except Exception as e:
            print(f"[inject] (no se pudo notificar al GBA: {e})")
        return 0

    try:
        txhash = w3.eth.send_raw_transaction(raw)
        txhash_bytes = txhash if isinstance(txhash, (bytes, bytearray)) else bytes.fromhex(
            txhash[2:] if isinstance(txhash, str) and txhash.startswith("0x") else txhash
        )
        txhash_hex = "0x" + txhash_bytes.hex()
        print(f"[inject] enviada, txhash = {txhash_hex}")
        print(f"[inject] explorador: https://sepolia.etherscan.io/tx/{txhash_hex}")
        try:
            send_tx_result(transport, TXRESULT_BROADCAST_OK, txhash=bytes(txhash_bytes))
        except Exception as e:
            print(f"[inject] (no se pudo notificar al GBA: {e})")
        return 0
    except Exception as e:
        # cualquier error del RPC (reverted, underpriced, intrinsic gas,
        # nonce too low, etc) lo propagamos al GBA para que el usuario lo
        # vea en pantalla. El mensaje se trunca a 64 bytes en el firmware.
        msg = str(e)
        # web3 mete el error completo con stacktrace; nos quedamos con la
        # primera linea relevante.
        short = msg.split("\n")[0][:200]
        print(f"[inject] ERROR broadcast: {short}")
        try:
            send_tx_result(transport, TXRESULT_BROADCAST_ERR, errmsg=short)
        except Exception as e2:
            print(f"[inject] (no se pudo notificar al GBA: {e2})")
        return 4


if __name__ == "__main__":
    sys.exit(main())
