#!/usr/bin/env python3
"""Standalone reimplementation of `gbafix` (devkitPro/gba-tools).

Patches a .gba ROM so that it passes the Game Boy Advance BIOS check:
writes the Nintendo logo at 0x04..0xA0, fills the header with the
title / code / fixed-0x96 byte, and computes the complement check (0xBD).

Usage:
    python3 tools/gbafix.py coldpakku.gba [-t TITLE] [-c CODE] [-m MAKER]

Without this, the ROM gets stuck on the Nintendo logo screen when booting
on real hardware (emulators such as mGBA usually skip the check).

Reference: https://problemkaputt.de/gbatek.htm#gbacartridgeheader
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Nintendo logo (156 bytes, offsets 0x004-0x09F of the GBA header).
# Fixed compressed bitmap, identical on every cartridge.
NINTENDO_LOGO = bytes.fromhex(
    "24ffae51699aa2213d84820a84e409ad"
    "11248b98c0817f21a352be199309ce20"
    "10464a4af82731ec58c7e83382e3cebf"
    "85f4df94ce4b09c194568ac01372a7fc"
    "9f844d73a3ca9a615897a327fc039876"
    "231dc7610304ae56bf38840040a70efd"
    "ff52fe036f9530f197fbc08560d68025"
    "a963be03014e38e2f9a234ffbb3e0344"
    "780090cb88113a9465c07c6387f03caf"
    "d625e48b380aac7221d4f807"
)
# The official devkitPro/gba-tools array (gbafix.c) is exactly 156 bytes.
# If this fires, the copy above got mangled.
if len(NINTENDO_LOGO) != 156:
    raise SystemExit(f"Nintendo logo is {len(NINTENDO_LOGO)} bytes, must be 156")


def patch_header(rom: bytearray, title: str, code: str, maker: str, version: int = 0) -> None:
    if len(rom) < 0xC0:
        raise SystemExit(f"ROM too small ({len(rom)} bytes), has no GBA header")

    # 0x004-0x09F: Nintendo logo (156 bytes)
    rom[0x004:0x0A0] = NINTENDO_LOGO

    # 0x0A0-0x0AB: title (12 bytes, ASCII upper, padded with 0x00)
    title_bytes = title.upper().encode("ascii", errors="replace")[:12]
    rom[0x0A0:0x0AC] = title_bytes.ljust(12, b"\x00")

    # 0x0AC-0x0AF: game code (4 bytes ASCII)
    code_bytes = code.encode("ascii")[:4]
    rom[0x0AC:0x0B0] = code_bytes.ljust(4, b"\x00")

    # 0x0B0-0x0B1: maker code (2 bytes ASCII)
    maker_bytes = maker.encode("ascii")[:2]
    rom[0x0B0:0x0B2] = maker_bytes.ljust(2, b"\x00")

    # 0x0B2: fixed value (must be 0x96)
    rom[0x0B2] = 0x96

    # 0x0B3: main unit code (0x00 = GBA)
    rom[0x0B3] = 0x00

    # 0x0B4: device type
    rom[0x0B4] = 0x00

    # 0x0B5-0x0BB: reserved (7 bytes, zero)
    for i in range(0x0B5, 0x0BC):
        rom[i] = 0x00

    # 0x0BC: software version
    rom[0x0BC] = version & 0xFF

    # 0x0BD: complement check
    # checksum = (- (0x19 + sum(rom[0xA0..0xBC]))) & 0xFF
    s = sum(rom[0x0A0:0x0BD])
    rom[0x0BD] = (-(0x19 + s)) & 0xFF

    # 0x0BE-0x0BF: reserved (2 bytes, zero)
    rom[0x0BE] = 0x00
    rom[0x0BF] = 0x00


def verify_header(rom: bytes) -> bool:
    if rom[0x004:0x0A0] != NINTENDO_LOGO:
        print("FAIL: Nintendo logo mismatch", file=sys.stderr)
        return False
    if rom[0x0B2] != 0x96:
        print(f"FAIL: byte 0xB2 = 0x{rom[0x0B2]:02X}, expected 0x96", file=sys.stderr)
        return False
    s = sum(rom[0x0A0:0x0BD])
    expected = (-(0x19 + s)) & 0xFF
    if rom[0x0BD] != expected:
        print(f"FAIL: complement check 0x{rom[0x0BD]:02X}, expected 0x{expected:02X}", file=sys.stderr)
        return False
    return True


def main() -> int:
    ap = argparse.ArgumentParser(description="Patch a GBA ROM header (drop-in gbafix replacement)")
    ap.add_argument("rom", type=Path)
    ap.add_argument("-t", "--title", default="COLDPAKKU", help="game title (max 12 chars)")
    ap.add_argument("-c", "--code", default="GSIE", help="4-char game code")
    ap.add_argument("-m", "--maker", default="00", help="2-char maker code")
    ap.add_argument("-v", "--version", type=int, default=0, help="software version (0-255)")
    ap.add_argument("--check", action="store_true", help="only verify, do not patch")
    args = ap.parse_args()

    data = bytearray(args.rom.read_bytes())
    if args.check:
        ok = verify_header(bytes(data))
        print("OK" if ok else "INVALID")
        return 0 if ok else 1

    patch_header(data, args.title, args.code, args.maker, args.version)
    args.rom.write_bytes(bytes(data))
    assert verify_header(bytes(data))
    print(f"patched {args.rom} ({len(data)} bytes)")
    print(f"  title:    {args.title!r}")
    print(f"  code:     {args.code!r}")
    print(f"  maker:    {args.maker!r}")
    print(f"  checksum: 0x{data[0x0BD]:02X}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
