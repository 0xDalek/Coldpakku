// Keccak-256 wrapper. Re-exports the one from @noble/hashes so the rest
// of the code doesn't have to import the long path, and adds the typical
// Ethereum helpers (concat + keccak in a single step).

import { keccak_256 } from "@noble/hashes/sha3";

import type { Hex } from "./types";
import { bytesToHex } from "./hex";

export { bytesToHex, hexToBytes } from "./hex";

export function keccak256(data: Uint8Array): Uint8Array {
  return keccak_256(data);
}

export function keccak256Hex(data: Uint8Array): Hex {
  return ("0x" + bytesToHex(keccak_256(data))) as Hex;
}

export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const a of arrays) total += a.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

export function utf8ToBytes(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}
