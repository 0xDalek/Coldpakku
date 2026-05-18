"""Build an Ethereum transaction, sign it with the GBA (which parses the
RLP on-device), and inject it onto the network via RPC.

Typical usage (mGBA on localhost):
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

Difference vs. the previous version: we no longer hash on the host and
ask the GBA to blind-sign. We now send raw RLP bytes and the GBA
decodes + hashes + shows the parsed fields before signing. The bridge
can no longer lie to the user about to/value/data.
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
    """Return the blob the GBA will parse and hash:
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
    raise SystemExit(f"unknown transport: {args.transport}")


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--rpc", required=True)
    p.add_argument("--transport", choices=["socket", "serial"], default="socket")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=12345)
    p.add_argument("--serial-port", default="/dev/ttyACM0",
                   help="serial port of the Pico bridge (default /dev/ttyACM0)")
    p.add_argument("--baud", type=int, default=115200)
    p.add_argument("--to", required=True)
    p.add_argument("--value-wei", required=True, type=parse_int)
    p.add_argument("--data", default="0x")
    p.add_argument("--address-from", required=True,
                   help="expected signer address (the one shown by the GBA)")
    p.add_argument("--no-broadcast", action="store_true",
                   help="sign but do not send the tx; useful for auditing")
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

    print(f"[inject] connecting via {args.transport}...")
    transport = build_transport(args)
    print(f"[inject] waiting for READY, confirm the tx on the GBA...")
    sig = perform_signing(transport, payload)
    if sig is None:
        print("[inject] user CANCELLED on the GBA")
        return 2

    print(f"[inject] raw signature: {sig.hex()}")
    expected_addr = to_canonical_address(args.address_from)
    rec = recover_address(h, sig, expected_addr)
    if rec is None:
        print("[inject] ERROR: could not recover the expected address — invalid signature")
        return 3
    canonical, recid = rec
    print(f"[inject] canonical signature (v=27+{recid}): {canonical.hex()}")

    raw = assemble_signed_rlp(tx, canonical)
    print(f"[inject] serialized tx: 0x{raw.hex()[:80]}... ({len(raw)} bytes)")

    # Deterministic hash of the signed tx (what you will see on etherscan).
    # We compute it always, even on --no-broadcast, so the GBA can show
    # the hash on its TX RESULT screen.
    final_txhash = keccak(raw)

    if args.no_broadcast:
        print(f"[inject] --no-broadcast: stopping before sending")
        print(f"[inject] hash it would have if sent: 0x{final_txhash.hex()}")
        try:
            send_tx_result(transport, TXRESULT_NO_BROADCAST, txhash=final_txhash)
        except Exception as e:
            print(f"[inject] (could not notify the GBA: {e})")
        return 0

    try:
        txhash = w3.eth.send_raw_transaction(raw)
        txhash_bytes = txhash if isinstance(txhash, (bytes, bytearray)) else bytes.fromhex(
            txhash[2:] if isinstance(txhash, str) and txhash.startswith("0x") else txhash
        )
        txhash_hex = "0x" + txhash_bytes.hex()
        print(f"[inject] sent, txhash = {txhash_hex}")
        print(f"[inject] explorer: https://sepolia.etherscan.io/tx/{txhash_hex}")
        try:
            send_tx_result(transport, TXRESULT_BROADCAST_OK, txhash=bytes(txhash_bytes))
        except Exception as e:
            print(f"[inject] (could not notify the GBA: {e})")
        return 0
    except Exception as e:
        # any RPC error (reverted, underpriced, intrinsic gas, nonce too
        # low, etc) is propagated to the GBA so the user sees it on
        # screen. The firmware truncates the message at 64 bytes.
        msg = str(e)
        # web3 includes the full error with stacktrace; we keep only the
        # first relevant line.
        short = msg.split("\n")[0][:200]
        print(f"[inject] ERROR broadcast: {short}")
        try:
            send_tx_result(transport, TXRESULT_BROADCAST_ERR, errmsg=short)
        except Exception as e2:
            print(f"[inject] (could not notify the GBA: {e2})")
        return 4


if __name__ == "__main__":
    sys.exit(main())
