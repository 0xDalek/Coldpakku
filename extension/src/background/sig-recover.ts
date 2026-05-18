// Recovery helpers for signatures coming from the GBA (with v=0xFE
// sentinel). Split out from transport.ts because that file used to
// depend on WebSerial's SerialPort types, which are not available in
// the MV3 service worker.

import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak256 } from "../lib/keccak";

const SECP256K1_N = BigInt(
  "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
);
const SECP256K1_HALF_N = SECP256K1_N >> 1n;

/** Given the v=0xFE signature from the GBA and the expected address (the
 * GBA's own), find the recid (0 or 1) that recovers correctly. Returns
 * r, s normalized to low-s and a coherent yParity. */
export function recoverRecid(
  digest32: Uint8Array,
  sig65: Uint8Array,
  expectedAddrBytes: Uint8Array,
): { r: Uint8Array; s: Uint8Array; yParity: 0 | 1 } {
  if (sig65.length !== 65) throw new Error("sig must be 65 bytes");
  let rInt = bytesToBigInt(sig65.slice(0, 32));
  let sInt = bytesToBigInt(sig65.slice(32, 64));

  // EIP-2: low-s. If we got high-s, normalize and flip the candidate recid.
  let needFlip = false;
  if (sInt > SECP256K1_HALF_N) {
    sInt = SECP256K1_N - sInt;
    needFlip = true;
  }

  for (const baseRecid of [0, 1] as const) {
    const recid = needFlip ? ((baseRecid ^ 1) as 0 | 1) : baseRecid;
    try {
      const sig = new secp256k1.Signature(rInt, sInt).addRecoveryBit(recid);
      const pubKey = sig.recoverPublicKey(digest32).toRawBytes(false); // 65B uncompressed
      const pubXY = pubKey.slice(1); // strip 0x04 prefix
      const addr = keccak256(pubXY).slice(12);
      if (bytesEqual(addr, expectedAddrBytes)) {
        return {
          r: bigIntToBytes32(rInt),
          s: bigIntToBytes32(sInt),
          yParity: recid,
        };
      }
    } catch {
      // continue with the next recid
    }
  }
  throw new Error("no valid recid: signature does not recover to the expected address");
}

function bytesToBigInt(b: Uint8Array): bigint {
  let n = 0n;
  for (const x of b) n = (n << 8n) | BigInt(x);
  return n;
}

function bigIntToBytes32(n: bigint): Uint8Array {
  const out = new Uint8Array(32);
  for (let i = 31; i >= 0 && n > 0n; i--) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}
