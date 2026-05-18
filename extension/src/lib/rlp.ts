// RLP encoder + EIP-2718 typed envelope encoders.
// Hand-rolled implementation to avoid pulling viem/ethers as a dep.
// Mirrors pc/protocol.py + eth_account.

import { concatBytes, hexToBytes } from "./keccak";
import type { Eip1559Tx, LegacyTx } from "./types";

// ============================================================================
// RLP base
// ============================================================================

type RlpInput = Uint8Array | RlpInput[];

export function rlpEncode(input: RlpInput): Uint8Array {
  if (input instanceof Uint8Array) {
    return encodeBytes(input);
  }
  if (Array.isArray(input)) {
    let body: Uint8Array = new Uint8Array(0);
    for (const item of input) {
      body = concatBytes(body, rlpEncode(item));
    }
    return concatBytes(encodeLength(body.length, 0xc0), body);
  }
  throw new Error(`rlp: unsupported type: ${typeof input}`);
}

function encodeBytes(b: Uint8Array): Uint8Array {
  if (b.length === 1 && b[0] < 0x80) return b;
  return concatBytes(encodeLength(b.length, 0x80), b);
}

function encodeLength(len: number, offset: number): Uint8Array {
  if (len < 56) return new Uint8Array([offset + len]);
  const lenBytes = intToMinimalBytes(len);
  return concatBytes(new Uint8Array([offset + 55 + lenBytes.length]), lenBytes);
}

/** Integer -> big-endian bytes with no leading zeros. 0 -> empty array
 * (RLP convention for leading zeros: encoded as the empty string). */
export function intToMinimalBytes(n: number | bigint): Uint8Array {
  if (typeof n === "number") n = BigInt(n);
  if (n < 0n) throw new Error("rlp: negative number");
  if (n === 0n) return new Uint8Array(0);
  const hex = n.toString(16);
  const padded = hex.length % 2 === 0 ? hex : "0" + hex;
  return hexToBytes(padded);
}

// ============================================================================
// EIP-1559 transaction (typed envelope 0x02)
// ============================================================================

/** Returns the serialized RLP (including the 0x02 envelope byte) ready
 * to send to the GBA via PROTO_TX_RLP. */
export function encodeEip1559(tx: Eip1559Tx): Uint8Array {
  const fields: RlpInput = [
    intToMinimalBytes(tx.chainId),
    intToMinimalBytes(tx.nonce),
    intToMinimalBytes(tx.maxPriorityFeePerGas),
    intToMinimalBytes(tx.maxFeePerGas),
    intToMinimalBytes(tx.gas),
    tx.to ? hexToBytes(tx.to) : new Uint8Array(0),
    intToMinimalBytes(tx.value),
    tx.data,
    encodeAccessList(tx.accessList),
  ];
  const body = rlpEncode(fields);
  return concatBytes(new Uint8Array([0x02]), body);
}

function encodeAccessList(list: Eip1559Tx["accessList"]): RlpInput {
  return list.map((item) => [
    hexToBytes(item.address),
    item.storageKeys.map((k) => hexToBytes(k)),
  ]);
}

/** Rebuilds the signed RLP (with r,s,v) ready for eth_sendRawTransaction
 * broadcast. The envelope is still 0x02 at the start. */
export function encodeEip1559Signed(
  tx: Eip1559Tx,
  yParity: 0 | 1,
  r: Uint8Array,
  s: Uint8Array,
): Uint8Array {
  const fields: RlpInput = [
    intToMinimalBytes(tx.chainId),
    intToMinimalBytes(tx.nonce),
    intToMinimalBytes(tx.maxPriorityFeePerGas),
    intToMinimalBytes(tx.maxFeePerGas),
    intToMinimalBytes(tx.gas),
    tx.to ? hexToBytes(tx.to) : new Uint8Array(0),
    intToMinimalBytes(tx.value),
    tx.data,
    encodeAccessList(tx.accessList),
    intToMinimalBytes(yParity),
    stripLeadingZeros(r),
    stripLeadingZeros(s),
  ];
  const body = rlpEncode(fields);
  return concatBytes(new Uint8Array([0x02]), body);
}

// ============================================================================
// Legacy transaction (type 0, EIP-155)
// ============================================================================

/** RLP for signing (hash preimage): EIP-155 appends chainId, 0, 0 at the end. */
export function encodeLegacyForSigning(tx: LegacyTx): Uint8Array {
  const fields: RlpInput = [
    intToMinimalBytes(tx.nonce),
    intToMinimalBytes(tx.gasPrice),
    intToMinimalBytes(tx.gas),
    tx.to ? hexToBytes(tx.to) : new Uint8Array(0),
    intToMinimalBytes(tx.value),
    tx.data,
    intToMinimalBytes(tx.chainId),
    new Uint8Array(0),
    new Uint8Array(0),
  ];
  return rlpEncode(fields);
}

export function encodeLegacySigned(
  tx: LegacyTx,
  yParity: 0 | 1,
  r: Uint8Array,
  s: Uint8Array,
): Uint8Array {
  const v = BigInt(tx.chainId) * 2n + 35n + BigInt(yParity);
  const fields: RlpInput = [
    intToMinimalBytes(tx.nonce),
    intToMinimalBytes(tx.gasPrice),
    intToMinimalBytes(tx.gas),
    tx.to ? hexToBytes(tx.to) : new Uint8Array(0),
    intToMinimalBytes(tx.value),
    tx.data,
    intToMinimalBytes(v),
    stripLeadingZeros(r),
    stripLeadingZeros(s),
  ];
  return rlpEncode(fields);
}

function stripLeadingZeros(b: Uint8Array): Uint8Array {
  let i = 0;
  while (i < b.length - 1 && b[i] === 0) i++;
  return b.slice(i);
}
