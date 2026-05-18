"""Smoke test for firmware v4 (multi-opcode).

Exercises the three new flows against a real GBA (via the Pico USB-CDC)
or an emulator (via mGBA TCP socket):

  1. PROTO_GET_ADDRESS   -> should return the active address without
                            asking the user for A/B
  2. PROTO_PERSONAL_SIGN -> EIP-191 signature over a fixed message,
                            recovery -> address
  3. PROTO_TYPED_DATA    -> EIP-712 signature over a test ERC-2612
                            permit, recovery -> address

For each step the GBA displays the data on screen; press A to sign.

Usage:
    # Real hardware (Pico):
    PYTHONPATH=.venv-tools python3 pc/test_signing_v4.py \\
        --transport serial --serial-port /dev/ttyACM0

    # mGBA emulator:
    PYTHONPATH=.venv-tools python3 pc/test_signing_v4.py \\
        --transport socket --port 12345

The test does NOT sign any Ethereum tx (that is already covered by
metamask_inject.py). Here we only validate the new opcodes.
"""
from __future__ import annotations

import argparse
import sys

from eth_account.messages import encode_defunct, encode_typed_data
from eth_keys import keys
from eth_keys.exceptions import BadSignature
from eth_utils import to_checksum_address

from protocol import (
    perform_get_address,
    perform_personal_sign,
    perform_typed_data,
)
from sig_recover import normalize_low_s


# Test ERC-2612 permit (USDC on mainnet, placeholder data).
# The cool thing about EIP-712: if we compute the hashes correctly, the
# GBA's signature over keccak256(0x1901 || ds || mh) should recover the
# same address.
PERMIT_TYPED_DATA = {
    "types": {
        "EIP712Domain": [
            {"name": "name",              "type": "string"},
            {"name": "version",           "type": "string"},
            {"name": "chainId",           "type": "uint256"},
            {"name": "verifyingContract", "type": "address"},
        ],
        "Permit": [
            {"name": "owner",    "type": "address"},
            {"name": "spender",  "type": "address"},
            {"name": "value",    "type": "uint256"},
            {"name": "nonce",    "type": "uint256"},
            {"name": "deadline", "type": "uint256"},
        ],
    },
    "primaryType": "Permit",
    "domain": {
        "name": "USD Coin",
        "version": "2",
        "chainId": 1,
        "verifyingContract": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
    },
    "message": {
        "owner":    "0x0000000000000000000000000000000000000001",
        "spender":  "0xdEAD000000000000000042069420694206942069",
        "value":    1000000000,
        "nonce":    0,
        "deadline": 9999999999,
    },
}


def make_transport(args):
    if args.transport == "socket":
        from mgba_socket import MgbaSocketTransport
        return MgbaSocketTransport(args.host, args.port)
    if args.transport == "serial":
        from serial_transport import SerialTransport
        return SerialTransport(args.serial_port)
    raise SystemExit(f"unknown transport: {args.transport}")


def recover_from_sig(hash32: bytes, sig65: bytes) -> str:
    """Return the EIP-55 address that signed the hash, trying recid 0/1
    and normalizing low-s (same as the tx host). Raises if no recid
    yields a valid signature."""
    if len(sig65) != 65:
        raise ValueError("sig must be 65 bytes")
    r_int = int.from_bytes(sig65[:32], "big")
    s_int = int.from_bytes(sig65[32:64], "big")
    for recid in (0, 1):
        try:
            sig_obj = keys.Signature(vrs=(recid, r_int, s_int))
            pub = sig_obj.recover_public_key_from_msg_hash(hash32)
            return to_checksum_address(pub.to_canonical_address())
        except BadSignature:
            continue
    # If the sig came in low-s form, try normalizing first (uECC already
    # produces low-s natively in v4, but just in case).
    for recid in (0, 1):
        try:
            r2, s2, recid2 = normalize_low_s(r_int, s_int, recid)
            sig_obj = keys.Signature(vrs=(recid2, r2, s2))
            pub = sig_obj.recover_public_key_from_msg_hash(hash32)
            return to_checksum_address(pub.to_canonical_address())
        except BadSignature:
            continue
    raise RuntimeError("no recid recovers a valid pubkey")


def step_get_address(transport):
    print("\n[1/3] PROTO_GET_ADDRESS")
    print("    asking the GBA for its address (does not require A)...")
    addr_raw = perform_get_address(transport)
    addr = to_checksum_address(addr_raw.hex())
    print(f"    address: {addr}")
    return addr


def step_personal_sign(transport, expected_addr):
    print("\n[2/3] PROTO_PERSONAL_SIGN")
    msg = b"GBA Signer v4 personal_sign smoke test\n"
    print(f"    msg ({len(msg)} bytes): {msg.decode()!r}")
    print("    --> look at the GBA and press A to sign")
    sig = perform_personal_sign(transport, msg)
    if sig is None:
        print("    USER CANCELLED")
        return False

    sm = encode_defunct(primitive=msg)
    eip191_hash = sm.body  # encode_defunct returns SignableMessage
    # eth_account ya da el hash final via .signable_message_hash()
    from eth_account._utils.signing import _hash_eip191_message
    eip191_hash = _hash_eip191_message(sm)
    recovered = recover_from_sig(eip191_hash, sig)
    print(f"    sig (65B): {sig.hex()}")
    print(f"    recovered: {recovered}")
    print(f"    expected : {expected_addr}")
    if recovered.lower() != expected_addr.lower():
        print("    [FAIL] recovered != expected")
        return False
    print("    [OK] personal_sign verified")
    return True


def step_typed_data(transport, expected_addr):
    print("\n[3/3] PROTO_TYPED_DATA")
    sm = encode_typed_data(full_message=PERMIT_TYPED_DATA)
    domain_sep = sm.header
    msg_hash   = sm.body
    digest = sm.body  # encode_typed_data returns SignableMessage:
    # version=0x01, header=domainSeparator, body=hashStruct(message)
    # The final EIP-712 digest is keccak(0x19 || 0x01 || header || body),
    # which the GBA computes internally.
    from eth_account._utils.signing import _hash_eip191_message
    eip712_digest = _hash_eip191_message(sm)

    # Human text we send to the GBA so the user can verify.
    domain = PERMIT_TYPED_DATA["domain"]
    msg = PERMIT_TYPED_DATA["message"]
    human_lines = [
        "EIP-712 PERMIT (test)",
        "",
        f"domain.name: {domain['name']}",
        f"version    : {domain['version']}",
        f"chainId    : {domain['chainId']}",
        f"contract   : {domain['verifyingContract'][:6]}..{domain['verifyingContract'][-4:]}",
        "",
        "Permit:",
        f"  owner   : {msg['owner'][:6]}..{msg['owner'][-4:]}",
        f"  spender : {msg['spender'][:6]}..{msg['spender'][-4:]}",
        f"  value   : {msg['value']}",
        f"  nonce   : {msg['nonce']}",
        f"  deadline: {msg['deadline']}",
    ]
    human_text = "\n".join(human_lines).encode("utf-8")

    print(f"    domainSep: {domain_sep.hex()}")
    print(f"    msgHash  : {msg_hash.hex()}")
    print(f"    digest   : {eip712_digest.hex()}")
    print("    --> look at the GBA, navigate with L/R, press A to sign")

    sig = perform_typed_data(transport, domain_sep, msg_hash, human_text)
    if sig is None:
        print("    USER CANCELLED")
        return False

    recovered = recover_from_sig(eip712_digest, sig)
    print(f"    sig (65B): {sig.hex()}")
    print(f"    recovered: {recovered}")
    print(f"    expected : {expected_addr}")
    if recovered.lower() != expected_addr.lower():
        print("    [FAIL] recovered != expected")
        return False
    print("    [OK] typed_data verified")
    return True


def main():
    p = argparse.ArgumentParser(description="firmware v4 smoke test")
    p.add_argument("--transport", choices=["socket", "serial"], required=True)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=12345)
    p.add_argument("--serial-port", default="/dev/ttyACM0")
    p.add_argument("--skip", choices=["addr", "personal", "typed"], action="append", default=[])
    args = p.parse_args()

    transport = make_transport(args)
    try:
        addr = None
        if "addr" not in args.skip:
            addr = step_get_address(transport)
        if addr is None:
            print("\n[!] no address; assuming you know the GBA's and read it manually")
            sys.exit(1)
        ok1 = ("personal" in args.skip) or step_personal_sign(transport, addr)
        ok2 = ("typed"    in args.skip) or step_typed_data(transport, addr)
        if not (ok1 and ok2):
            sys.exit(1)
        print("\n[OK] all v4 flows verified")
    finally:
        transport.close()


if __name__ == "__main__":
    main()
