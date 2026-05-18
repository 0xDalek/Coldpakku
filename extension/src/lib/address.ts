// Helpers for Ethereum addresses: validation + EIP-55 checksum.

import { keccak256, bytesToHex, hexToBytes } from "./keccak";
import type { Address, Hex } from "./types";

/** Turns 20 raw bytes into an EIP-55 checksummed Address. */
export function toChecksumAddress(addr20: Uint8Array): Address {
  if (addr20.length !== 20) throw new Error("address must be 20 bytes");
  const lower = bytesToHex(addr20);          // 40 hex chars without 0x
  const hash = keccak256(new TextEncoder().encode(lower));
  let out = "0x";
  for (let i = 0; i < lower.length; i++) {
    const ch = lower[i];
    if (ch >= "0" && ch <= "9") {
      out += ch;
    } else {
      // If the matching hash nibble is >= 8, uppercase the letter.
      const nibble = (hash[i >> 1] >> (i % 2 === 0 ? 4 : 0)) & 0xf;
      out += nibble >= 8 ? ch.toUpperCase() : ch;
    }
  }
  return out as Address;
}

export function isValidAddress(s: string): s is Address {
  if (!/^0x[0-9a-fA-F]{40}$/.test(s)) return false;
  // if there are any uppercase letters, it must checksum correctly
  if (s !== s.toLowerCase() && s !== s.toUpperCase()) {
    const expected = toChecksumAddress(hexToBytes(s));
    return expected === s;
  }
  return true;
}

export function addressToBytes(a: Address): Uint8Array {
  return hexToBytes(a);
}

/** "0xABCD...EF12" — short form for UI. */
export function shortAddress(a: Address | string): string {
  const s = a.toLowerCase();
  return s.slice(0, 6) + "..." + s.slice(-4);
}

/** Returns the canonical representation (lowercase + checksum) used by
 * accountsChanged / eth_accounts events, per EIP-55. */
export function normalizeAddress(a: Hex): Address {
  return toChecksumAddress(hexToBytes(a));
}
