// EIP-712 typed data hashing.
// Minimal hand-rolled implementation (no viem/ethers) to keep the bundle
// small. Based on https://eips.ethereum.org/EIPS/eip-712 and the
// MetaMask V4 spec.
//
// Inputs: the typical eth_signTypedData_v4 JSON:
//   {
//     "types":       { "EIP712Domain": [...], "Permit": [...], ... },
//     "domain":      { name, version, chainId, verifyingContract, salt },
//     "primaryType": "Permit",
//     "message":     { ... }
//   }
//
// Output:
//   - domainSeparator (32B) and messageHash (32B) sent to the GBA.
//   - The final digest (which the GBA computes) is:
//       keccak256(0x19 || 0x01 || domainSeparator || messageHash)
//   - We also generate a human "pretty" text that the GBA shows to the
//     user for verification before signing.

import { keccak256, concatBytes, hexToBytes, utf8ToBytes } from "./keccak";

interface TypedField {
  name: string;
  type: string;
}

export interface TypedData {
  types: Record<string, TypedField[]>;
  primaryType: string;
  domain: Record<string, any>;
  message: Record<string, any>;
}

export interface TypedDataHashes {
  domainSeparator: Uint8Array;
  messageHash: Uint8Array;
  digest: Uint8Array;
}

export function hashTypedData(td: TypedData): TypedDataHashes {
  const domainSeparator = hashStruct("EIP712Domain", td.domain, td.types);
  const messageHash = hashStruct(td.primaryType, td.message, td.types);
  const digest = keccak256(
    concatBytes(new Uint8Array([0x19, 0x01]), domainSeparator, messageHash),
  );
  return { domainSeparator, messageHash, digest };
}

/** Finds every (custom) struct type referenced by `primary`, in
 * alphabetical order (with `primary` first). EIP-712 5.1. */
function findDependencies(
  primary: string,
  types: Record<string, TypedField[]>,
  found: Set<string> = new Set(),
): string[] {
  if (found.has(primary)) return [];
  if (!types[primary]) return [];
  found.add(primary);
  const deps: string[] = [];
  for (const f of types[primary]) {
    const t = baseType(f.type);
    if (types[t]) {
      const sub = findDependencies(t, types, found);
      for (const s of sub) deps.push(s);
    }
  }
  return [primary, ...deps.filter((d) => d !== primary).sort()];
}

function encodeType(primary: string, types: Record<string, TypedField[]>): string {
  const deps = findDependencies(primary, types);
  const head = deps[0];
  const tail = deps.slice(1).sort();
  const all = [head, ...tail];
  return all
    .map((t) => `${t}(${types[t].map((f) => `${f.type} ${f.name}`).join(",")})`)
    .join("");
}

function typeHash(primary: string, types: Record<string, TypedField[]>): Uint8Array {
  return keccak256(utf8ToBytes(encodeType(primary, types)));
}

function hashStruct(
  primary: string,
  data: Record<string, any>,
  types: Record<string, TypedField[]>,
): Uint8Array {
  const encoded = encodeData(primary, data, types);
  return keccak256(encoded);
}

function encodeData(
  primary: string,
  data: Record<string, any>,
  types: Record<string, TypedField[]>,
): Uint8Array {
  const fields = types[primary];
  if (!fields) throw new Error(`EIP-712: unknown type ${primary}`);
  const parts: Uint8Array[] = [typeHash(primary, types)];
  for (const f of fields) {
    parts.push(encodeValue(f.type, data[f.name], types));
  }
  return concatBytes(...parts);
}

function baseType(t: string): string {
  const i = t.indexOf("[");
  return i === -1 ? t : t.substring(0, i);
}

function encodeValue(
  type: string,
  value: any,
  types: Record<string, TypedField[]>,
): Uint8Array {
  // Arrays
  if (type.endsWith("]")) {
    const inner = type.substring(0, type.lastIndexOf("["));
    if (!Array.isArray(value)) {
      throw new Error(`EIP-712: value for ${type} must be an array`);
    }
    const parts = value.map((v) => encodeValue(inner, v, types));
    return keccak256(concatBytes(...parts));
  }

  // Custom struct
  if (types[type]) {
    return hashStruct(type, value, types);
  }

  // Primitives
  if (type === "string") {
    return keccak256(utf8ToBytes(String(value)));
  }
  if (type === "bytes") {
    const bytes = typeof value === "string" ? hexToBytes(value) : (value as Uint8Array);
    return keccak256(bytes);
  }
  if (type === "address") {
    return padLeft32(hexToBytes(String(value)));
  }
  if (type === "bool") {
    const b = new Uint8Array(32);
    b[31] = value ? 1 : 0;
    return b;
  }
  if (type.startsWith("uint")) {
    return uintToWord32(value);
  }
  if (type.startsWith("int")) {
    return intToWord32(value);
  }
  if (type.startsWith("bytes")) {
    // fixed-size bytesN
    const n = parseInt(type.substring(5), 10);
    if (isNaN(n) || n < 1 || n > 32) {
      throw new Error(`EIP-712: invalid bytesN type ${type}`);
    }
    const bytes = typeof value === "string" ? hexToBytes(value) : (value as Uint8Array);
    if (bytes.length !== n) {
      throw new Error(`EIP-712: ${type} must be ${n} bytes, got ${bytes.length}`);
    }
    return padRight32(bytes);
  }
  throw new Error(`EIP-712: unsupported type ${type}`);
}

function padLeft32(b: Uint8Array): Uint8Array {
  if (b.length === 32) return b;
  if (b.length > 32) throw new Error("padLeft32: input > 32 bytes");
  const out = new Uint8Array(32);
  out.set(b, 32 - b.length);
  return out;
}

function padRight32(b: Uint8Array): Uint8Array {
  if (b.length === 32) return b;
  if (b.length > 32) throw new Error("padRight32: input > 32 bytes");
  const out = new Uint8Array(32);
  out.set(b, 0);
  return out;
}

function uintToWord32(v: any): Uint8Array {
  let n: bigint;
  if (typeof v === "bigint") n = v;
  else if (typeof v === "number") n = BigInt(v);
  else if (typeof v === "string") n = BigInt(v);
  else throw new Error(`EIP-712: uint requires bigint/number/string`);
  if (n < 0n) throw new Error(`EIP-712: negative uint`);
  const out = new Uint8Array(32);
  for (let i = 31; i >= 0 && n > 0n; i--) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
}

function intToWord32(v: any): Uint8Array {
  let n: bigint;
  if (typeof v === "bigint") n = v;
  else if (typeof v === "number") n = BigInt(v);
  else if (typeof v === "string") n = BigInt(v);
  else throw new Error(`EIP-712: int requires bigint/number/string`);
  // 256-bit two's complement
  const mask = (1n << 256n) - 1n;
  const u = n & mask;
  return uintToWord32(u);
}

// ============================================================================
// Human-readable pretty-printer for display on the GBA
// ============================================================================

/** Serializes typed data as plain text for the user. Caps the output at
 * `maxBytes` bytes (truncating with "..."). The GBA shows this plus the
 * hashes for manual verification. */
export function prettyPrintTypedData(td: TypedData, maxBytes = 4000): string {
  const lines: string[] = [];
  lines.push(`EIP-712 ${td.primaryType}`);
  lines.push("");
  lines.push("domain:");
  for (const [k, v] of Object.entries(td.domain)) {
    lines.push(`  ${k}: ${formatValue(v)}`);
  }
  lines.push("");
  lines.push(`${td.primaryType}:`);
  formatStruct(td.message, "  ", lines);
  let out = lines.join("\n");
  if (out.length > maxBytes) {
    out = out.substring(0, maxBytes - 4) + "\n...";
  }
  return out;
}

function formatStruct(obj: any, indent: string, lines: string[]) {
  for (const [k, v] of Object.entries(obj)) {
    if (v && typeof v === "object" && !Array.isArray(v) && !(v instanceof Uint8Array)) {
      lines.push(`${indent}${k}:`);
      formatStruct(v, indent + "  ", lines);
    } else if (Array.isArray(v)) {
      lines.push(`${indent}${k}: [${v.length} items]`);
    } else {
      lines.push(`${indent}${k}: ${formatValue(v)}`);
    }
  }
}

function formatValue(v: any): string {
  if (typeof v === "string") {
    if (v.startsWith("0x") && v.length === 42) {
      // Address: short form
      return v.slice(0, 10) + ".." + v.slice(-6);
    }
    return v;
  }
  if (typeof v === "bigint" || typeof v === "number") {
    return v.toString();
  }
  if (v instanceof Uint8Array) {
    let h = "0x";
    for (const b of v) h += b.toString(16).padStart(2, "0");
    return h.length > 18 ? h.slice(0, 14) + ".." + h.slice(-4) : h;
  }
  return JSON.stringify(v);
}
