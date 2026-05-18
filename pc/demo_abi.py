"""Demo of the new DECODED page in confirm_tx.

Sends 3 simulated transactions to the GBA and lets you visually validate:
  1. transfer(0xAaBb..CcDd, 1.5M)            -> "ERC-20 transfer" + decoded
  2. approve(0x2222..2222, max_uint256)      -> "approve INFINITE (!)" + box warning
  3. setApprovalForAll(0x3333..3333, true)   -> "approve ALL NFTS (!)" + box warning

No RPC, no broadcasting. It only builds an unsigned RLP and sends it
over USB-CDC to the Pico bridge so the GBA parses and displays it.

Usage:
    python3 pc/demo_abi.py [--serial-port /dev/ttyACM0] [--chain-id 11155111]

Prerequisites:
  - GBA powered on with the wallet unlocked (PIN entered), on the
    "AWAITING TRANSACTION" screen.
  - Pico connected by USB and enumerated as /dev/ttyACM0.
  - The CLI chainId == chainId locked in the GBA (default: Sepolia).
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "pc"))

import rlp

from protocol import RlpTx, perform_signing


# ABI selectors
SEL_TRANSFER             = bytes.fromhex("a9059cbb")
SEL_APPROVE              = bytes.fromhex("095ea7b3")
SEL_SET_APPROVAL_FOR_ALL = bytes.fromhex("a22cb465")


def pad_addr(addr_hex: str) -> bytes:
    a = bytes.fromhex(addr_hex.removeprefix("0x"))
    assert len(a) == 20, f"address must be 20 bytes, not {len(a)}"
    return b"\x00" * 12 + a


def be_uint256(v: int) -> bytes:
    return v.to_bytes(32, "big")


def build_rlp(chain_id: int, to_hex: str, data: bytes, value_wei: int = 0) -> bytes:
    """Build the RLP for an EIP-1559 unsigned tx."""
    to = bytes.fromhex(to_hex.removeprefix("0x"))
    assert len(to) == 20
    fields = [
        chain_id,
        42,                 # nonce
        1_000_000_000,      # maxPriorityFeePerGas (1 gwei)
        20_000_000_000,     # maxFeePerGas (20 gwei)
        100_000,            # gas
        to,
        value_wei,
        data,
        [],                 # empty access list
    ]
    return b"\x02" + rlp.encode(fields)


def banner(s: str) -> None:
    print()
    print("=" * 60)
    print(s)
    print("=" * 60)


def run_case(transport, name: str, expected: str, rlp_bytes: bytes) -> None:
    banner(name)
    print("Expected on the GBA screen:")
    print(expected)
    print()
    print("Press Enter here when ready (will send the tx)...")
    input()
    print(f"  sending {len(rlp_bytes)} bytes of RLP...")
    sig = perform_signing(transport, RlpTx(rlp=rlp_bytes), timeout_s=120.0)
    if sig is None:
        print("  >>> user CANCELLED with B (expected if you just wanted to look)")
    else:
        print(f"  >>> user CONFIRMED with A; 65B signature = 0x{sig.hex()}")
    print("  (the GBA will return to AWAITING TRANSACTION in ~1s)")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--serial-port", default="/dev/ttyACM0")
    ap.add_argument("--chain-id", type=int, default=11155111,
                    help="chainId sent in the tx; must match the one "
                         "locked in the GBA (default Sepolia 11155111). "
                         "Mainnet=1, Polygon=137, Arbitrum=42161, OP=10, Base=8453.")
    ap.add_argument("--only", choices=("1", "2", "3"),
                    help="run only one case (1=transfer, 2=approve INF, 3=setApprovalForAll)")
    args = ap.parse_args()

    from serial_transport import SerialTransport
    print(f"opening {args.serial_port}...")
    transport = SerialTransport(device=args.serial_port)

    try:
        cases = []

        # Case 1: regular transfer
        data1 = SEL_TRANSFER + pad_addr("0xAaBbCcDdEeFf00112233445566778899aAbBcCdD") + be_uint256(1_500_000)
        rlp1 = build_rlp(args.chain_id, "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238", data1)
        expected1 = """\
  Page 0 (header):
    data: ERC-20 transfer
    statusbar: A sign  B cancel  R decoded >

  Press R once for the DECODED page:
    titlebar: TX DATA          DECODED
    function:
      transfer  (ERC-20)
    recipient:
      0xAaBbCcDdEeFf0011223344
      5566778899AaBbCcDdEeFf01..  (eip-55 mixed case)
    amount (raw uint256):
      1500000
    (decimals unknown)
    statusbar: A sign  B cancel  L< R> hex

  Press R again: hex dump as before.
  Press B to go back to the menu (I don't want to burn my real nonce).
"""
        cases.append(("Case 1/3: regular transfer", expected1, rlp1))

        # Case 2: approve INFINITE
        data2 = SEL_APPROVE + pad_addr("0x2222222222222222222222222222222222222222") + (b"\xff" * 32)
        rlp2 = build_rlp(args.chain_id, "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238", data2)
        expected2 = """\
  Page 0 (header):
    data: approve INFINITE (!)        <-- the "(!)" must be clearly visible
    statusbar: A sign  B cancel  R decoded >

  Press R once for the DECODED page:
    titlebar: TX DATA          INFINITE!
    function:
      approve   (ERC-20)
    +----------------------+
    |  INFINITE APPROVAL!  |          <-- ASCII box
    +----------------------+
    spender:
      0x2222222222222222222222
      2222222222222222222222222
    amount (raw uint256):
      2^256 - 1 (UNLIMITED)
    statusbar: A sign  B cancel  L< R> hex

  Press B to cancel.
"""
        cases.append(("Case 2/3: approve INFINITE", expected2, rlp2))

        # Case 3: setApprovalForAll (true)
        data3 = SEL_SET_APPROVAL_FOR_ALL + pad_addr("0x3333333333333333333333333333333333333333") + be_uint256(1)
        rlp3 = build_rlp(args.chain_id, "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238", data3)
        expected3 = """\
  Page 0 (header):
    data: approve ALL NFTS (!)
    statusbar: A sign  B cancel  R decoded >

  Press R once for the DECODED page:
    titlebar: TX DATA          ALL NFTS
    function:
      setApprovalForAll
    +----------------------+
    |  ALL NFTS APPROVED!  |
    +----------------------+
    operator:
      0x3333333333333333333333
      3333333333333333333333333
    approved: TRUE  (grant)
    grants operator FULL
    control of all NFTs in
    this collection.
    statusbar: A sign  B cancel  L< R> hex

  Press B to cancel.
"""
        cases.append(("Case 3/3: setApprovalForAll(true)", expected3, rlp3))

        if args.only:
            idx = int(args.only) - 1
            run_case(transport, *cases[idx])
        else:
            for c in cases:
                run_case(transport, *c)

        print()
        print("== end of demo ==")
        return 0
    finally:
        transport.close()


if __name__ == "__main__":
    sys.exit(main())
