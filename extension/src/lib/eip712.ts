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

// Caps mirrored in src/crypto/eip712.h and docs/PROTOCOL.md. The wire
// format and the on-device parser refuse anything bigger.
export const EIP712_MAX_TYPES             = 32;
export const EIP712_MAX_FIELDS_PER_TYPE   = 32;
export const EIP712_MAX_NAME_LEN          = 32;
export const EIP712_MAX_TYPE_LEN          = 40;
export const EIP712_MAX_STRING_LEN        = 1024;

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
// TLV serialization for the on-device parser (PROTO_TYPED_DATA v7 tree)
// ============================================================================

/** Thrown when the typed data does not fit in the parser's caps. The
 * caller (sign.ts) is expected to fall back to blind-only mode
 * (`tree_len = 0` on the wire) and log a warning, NOT abort the signing
 * — the GBA still gets the host-supplied hashes and pretty text. */
export class TLVTooBigError extends Error {}

/** Serializes a TypedData into the TLV format defined by
 * docs/PROTOCOL.md. Layout (all multi-byte ints big-endian):
 *
 *   1B num_types
 *   for each type: 1B name_len + name + 1B num_fields
 *                  + for each field: 1B fname_len + fname
 *                                  + 1B ftype_len + ftype
 *   1B primary_type_index
 *   <domain_values> (driven by types[0] = EIP712Domain)
 *   <message_values> (driven by types[primary])
 *
 * Convention: index 0 is always EIP712Domain. Index 1 is the primaryType
 * unless EIP712Domain references a struct (rare; we DFS-collect deps in
 * declaration order to keep the layout deterministic).
 *
 * Arrays (T[] / T[N]) are serialized as `4B count + count items`. The
 * on-device parser flags them as UNSUPPORTED in v0.2 but still walks
 * past the bytes so the framing stays in sync.
 */
export function serializeTypedDataTLV(td: TypedData): Uint8Array {
  if (!td.types || !td.types["EIP712Domain"]) {
    throw new Error("serializeTypedDataTLV: missing EIP712Domain in types");
  }
  if (!td.types[td.primaryType]) {
    throw new Error(`serializeTypedDataTLV: unknown primaryType ${td.primaryType}`);
  }

  // DFS-collect all referenced struct types, EIP712Domain first, then
  // the primary type, then any transitive dep of either, in discovery
  // order. This keeps the layout deterministic across the host and the
  // device, and lets the on-device parser do a single forward pass.
  const order: string[] = [];
  const seen = new Set<string>();
  function collect(typeName: string) {
    if (seen.has(typeName)) return;
    if (!td.types[typeName]) return; // primitive / atomic, skip
    seen.add(typeName);
    order.push(typeName);
    for (const f of td.types[typeName]) {
      collect(baseType(f.type));
    }
  }
  collect("EIP712Domain");
  collect(td.primaryType);

  if (order.length > EIP712_MAX_TYPES) {
    throw new TLVTooBigError(
      `serializeTypedDataTLV: ${order.length} types > EIP712_MAX_TYPES=${EIP712_MAX_TYPES}`,
    );
  }
  if (order[0] !== "EIP712Domain") {
    throw new Error("serializeTypedDataTLV: internal — EIP712Domain not at index 0");
  }
  const primaryIdx = order.indexOf(td.primaryType);
  if (primaryIdx < 0) {
    throw new Error(`serializeTypedDataTLV: primaryType ${td.primaryType} not in order`);
  }

  const parts: Uint8Array[] = [];
  const pushU8 = (v: number) => parts.push(new Uint8Array([v & 0xff]));
  const pushU32BE = (v: number) => {
    const b = new Uint8Array(4);
    b[0] = (v >>> 24) & 0xff;
    b[1] = (v >>> 16) & 0xff;
    b[2] = (v >>> 8) & 0xff;
    b[3] = v & 0xff;
    parts.push(b);
  };
  const pushBoundedAscii = (s: string, maxLen: number, label: string) => {
    const u = utf8ToBytes(s);
    if (u.length === 0) {
      throw new Error(`serializeTypedDataTLV: empty ${label}`);
    }
    if (u.length > maxLen) {
      throw new TLVTooBigError(
        `serializeTypedDataTLV: ${label} "${s}" length ${u.length} > ${maxLen}`,
      );
    }
    pushU8(u.length);
    parts.push(u);
  };

  // ---- type table ----
  pushU8(order.length);
  for (const typeName of order) {
    pushBoundedAscii(typeName, EIP712_MAX_NAME_LEN, "type name");
    const fields = td.types[typeName];
    if (fields.length === 0 || fields.length > EIP712_MAX_FIELDS_PER_TYPE) {
      throw new TLVTooBigError(
        `serializeTypedDataTLV: type ${typeName} has ${fields.length} fields (cap ${EIP712_MAX_FIELDS_PER_TYPE})`,
      );
    }
    pushU8(fields.length);
    for (const f of fields) {
      pushBoundedAscii(f.name, EIP712_MAX_NAME_LEN, `field name in ${typeName}`);
      pushBoundedAscii(f.type, EIP712_MAX_TYPE_LEN, `field type in ${typeName}`);
    }
  }

  // ---- primary type index ----
  pushU8(primaryIdx);

  // ---- value sections ----
  function writeStructValues(typeName: string, obj: any) {
    const fields = td.types[typeName];
    for (const f of fields) {
      writeValue(f.type, obj?.[f.name], typeName, f.name);
    }
  }

  function writeValue(typeStr: string, v: any, parentType: string, fieldName: string) {
    // Arrays: prefix 4B count + items. The on-device parser will tag
    // the whole tree as UNSUPPORTED in v0.2 but still consumes the
    // bytes so the framing stays valid (and a future v0.3 parser can
    // pick it up without protocol changes).
    if (typeStr.endsWith("]")) {
      const inner = typeStr.substring(0, typeStr.lastIndexOf("["));
      if (!Array.isArray(v)) {
        throw new Error(`array field ${parentType}.${fieldName} is not an array`);
      }
      pushU32BE(v.length);
      for (const item of v) writeValue(inner, item, parentType, fieldName);
      return;
    }
    // Nested struct: recurse with no extra framing — fields are written
    // back-to-back per declaration order, just like the parser reads.
    if (td.types[typeStr]) {
      writeStructValues(typeStr, v);
      return;
    }
    // string
    if (typeStr === "string") {
      const u = utf8ToBytes(String(v ?? ""));
      if (u.length > EIP712_MAX_STRING_LEN) {
        throw new TLVTooBigError(
          `serializeTypedDataTLV: string ${parentType}.${fieldName} length ${u.length} > ${EIP712_MAX_STRING_LEN}`,
        );
      }
      pushU32BE(u.length);
      parts.push(u);
      return;
    }
    // dynamic bytes
    if (typeStr === "bytes") {
      const u = typeof v === "string" ? hexToBytes(v) : (v as Uint8Array);
      if (u.length > EIP712_MAX_STRING_LEN) {
        throw new TLVTooBigError(
          `serializeTypedDataTLV: bytes ${parentType}.${fieldName} length ${u.length} > ${EIP712_MAX_STRING_LEN}`,
        );
      }
      pushU32BE(u.length);
      parts.push(u);
      return;
    }
    if (typeStr === "address") {
      const u = hexToBytes(String(v));
      if (u.length !== 20) {
        throw new Error(`address ${parentType}.${fieldName} expects 20 bytes, got ${u.length}`);
      }
      parts.push(u);
      return;
    }
    if (typeStr === "bool") {
      pushU8(v ? 1 : 0);
      return;
    }
    if (typeStr.startsWith("uint")) {
      const bits = parseUintBits(typeStr.substring(4));
      const N = bits / 8;
      parts.push(uintToBigEndian(v, N));
      return;
    }
    if (typeStr.startsWith("int")) {
      const bits = parseUintBits(typeStr.substring(3));
      const N = bits / 8;
      parts.push(intToBigEndian(v, N));
      return;
    }
    if (typeStr.startsWith("bytes")) {
      const N = parseInt(typeStr.substring(5), 10);
      if (isNaN(N) || N < 1 || N > 32) {
        throw new Error(`bad bytesN type ${typeStr}`);
      }
      const u = typeof v === "string" ? hexToBytes(v) : (v as Uint8Array);
      if (u.length !== N) {
        throw new Error(`${typeStr} field ${parentType}.${fieldName} expects ${N} bytes, got ${u.length}`);
      }
      parts.push(u);
      return;
    }
    throw new Error(`unsupported EIP-712 type "${typeStr}" at ${parentType}.${fieldName}`);
  }

  writeStructValues("EIP712Domain", td.domain);
  writeStructValues(td.primaryType, td.message);
  return concatBytes(...parts);
}

function parseUintBits(suffix: string): number {
  const bits = suffix === "" ? 256 : parseInt(suffix, 10);
  if (isNaN(bits) || bits < 8 || bits > 256 || bits % 8 !== 0) {
    throw new Error(`bad uint/int width "${suffix}"`);
  }
  return bits;
}

function uintToBigEndian(v: any, N: number): Uint8Array {
  let n: bigint;
  if (typeof v === "bigint") n = v;
  else if (typeof v === "number") n = BigInt(v);
  else if (typeof v === "string") n = BigInt(v);
  else throw new Error(`uint requires bigint/number/string, got ${typeof v}`);
  if (n < 0n) throw new Error(`uint cannot be negative`);
  const max = 1n << BigInt(N * 8);
  if (n >= max) throw new Error(`uint${N * 8} overflow`);
  const out = new Uint8Array(N);
  for (let i = N - 1; i >= 0 && n > 0n; i--) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
}

function intToBigEndian(v: any, N: number): Uint8Array {
  let n: bigint;
  if (typeof v === "bigint") n = v;
  else if (typeof v === "number") n = BigInt(v);
  else if (typeof v === "string") n = BigInt(v);
  else throw new Error(`int requires bigint/number/string, got ${typeof v}`);
  // Two's complement N-byte encoding.
  const mask = (1n << BigInt(N * 8)) - 1n;
  const u = n & mask;
  return uintToBigEndian(u, N);
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
