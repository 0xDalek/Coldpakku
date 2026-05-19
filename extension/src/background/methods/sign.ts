// Handlers for personal_sign (EIP-191) and eth_signTypedData_v4 (EIP-712).
// Both compute the hash on the host, show it in the popup and on the GBA,
// and read the signature back from the GBA. The GBA also does the hashing
// (personal) or signs the hashes it received (typed_data — blind sign).

import type { Address, Hex } from "../../lib/types";
import { toChecksumAddress } from "../../lib/address";
import { keccak256, utf8ToBytes, bytesToHex, hexToBytes } from "../../lib/keccak";
import {
  hashTypedData,
  prettyPrintTypedData,
  serializeTypedDataTLV,
  TLVTooBigError,
  type TypedData,
} from "../../lib/eip712";
import { PROTO_TYPED_TREE_MAX } from "../protocol";
import { RpcError } from "../rpc-passthrough";
import { withGbaSession } from "../serial-bridge";
import { recoverRecid } from "../sig-recover";
import {
  startActiveRequest,
  clearActiveRequest,
  type ConfirmRequest,
} from "../confirm-orchestrator";
import { assertConnected, mustAddressBytes } from "./_shared";

export async function personalSign(origin: string, [hexMsg, _addr]: [Hex, Address]): Promise<Hex> {
  await assertConnected(origin);
  const msg = hexToBytes(hexMsg);
  const addrBytes = await mustAddressBytes();
  const checksum = toChecksumAddress(addrBytes);

  // EIP-191 hash, same as the GBA: "\x19Ethereum Signed Message:\n<len>" + msg
  const prefix = utf8ToBytes(`\x19Ethereum Signed Message:\n${msg.length}`);
  const eip191 = keccak256(concatU8(prefix, msg));

  const cReq: ConfirmRequest = {
    kind: "personal_sign",
    origin,
    address: checksum,
    msgUtf8: tryDecodeUtf8(msg),
    msgHexLen: msg.length,
    eip191HashHex: ("0x" + bytesToHex(eip191)) as Hex,
  };
  const { cancelled } = startActiveRequest(cReq);
  try {
    const sig = await withGbaSession((session) => session.personalSign(msg));
    if (cancelled.cancelled) {
      throw new RpcError(4001, "User cancelled in extension popup.");
    }
    if (!sig) {
      throw new RpcError(4001, "User rejected on GBA (button B).");
    }
    const { r, s, yParity } = recoverRecid(eip191, sig, addrBytes);
    const out = new Uint8Array(65);
    out.set(r, 0);
    out.set(s, 32);
    out[64] = 27 + yParity;
    return ("0x" + bytesToHex(out)) as Hex;
  } finally {
    clearActiveRequest();
  }
}

export async function ethSignTypedData(origin: string, [_addr, jsonStr]: [Address, string]): Promise<Hex> {
  await assertConnected(origin);
  const td: TypedData = typeof jsonStr === "string" ? JSON.parse(jsonStr) : jsonStr;
  const { domainSeparator, messageHash, digest } = hashTypedData(td);
  const human = prettyPrintTypedData(td);
  const addrBytes = await mustAddressBytes();
  const checksum = toChecksumAddress(addrBytes);

  // Serialize the typed-data tree so the GBA can re-derive the hashes
  // on-device when the user requests parsed view (L+R combo). Any error
  // here is non-fatal: we fall back to the legacy blind-only flow by
  // sending tree_len = 0 on the wire. The pretty text + hashes are
  // unaffected.
  let treeBytes: Uint8Array = new Uint8Array(0);
  try {
    const tlv = serializeTypedDataTLV(td);
    if (tlv.length > PROTO_TYPED_TREE_MAX) {
      console.warn(
        `[Coldpakku] typed-data TLV (${tlv.length} B) exceeds PROTO_TYPED_TREE_MAX=${PROTO_TYPED_TREE_MAX}; falling back to blind-only.`,
      );
    } else {
      treeBytes = tlv;
    }
  } catch (err) {
    const reason = err instanceof TLVTooBigError ? "too big" : "unsupported";
    console.warn(
      `[Coldpakku] typed-data TLV (${reason}): ${err instanceof Error ? err.message : err}. Falling back to blind-only.`,
    );
  }

  const cReq: ConfirmRequest = {
    kind: "typed_data",
    origin,
    address: checksum,
    primaryType: td.primaryType,
    domainName: String(td.domain.name ?? ""),
    chainId: typeof td.domain.chainId === "string"
      ? parseInt(td.domain.chainId, 10)
      : Number(td.domain.chainId ?? 0),
    humanText: human,
    domainSepHex: ("0x" + bytesToHex(domainSeparator)) as Hex,
    msgHashHex: ("0x" + bytesToHex(messageHash)) as Hex,
    digestHex: ("0x" + bytesToHex(digest)) as Hex,
  };
  const { cancelled } = startActiveRequest(cReq);
  try {
    const sig = await withGbaSession((session) =>
      session.typedData(domainSeparator, messageHash, utf8ToBytes(human), treeBytes),
    );
    if (cancelled.cancelled) {
      throw new RpcError(4001, "User cancelled in extension popup.");
    }
    if (!sig) {
      throw new RpcError(4001, "User rejected on GBA (button B).");
    }
    const { r, s, yParity } = recoverRecid(digest, sig, addrBytes);
    const out = new Uint8Array(65);
    out.set(r, 0);
    out.set(s, 32);
    out[64] = 27 + yParity;
    return ("0x" + bytesToHex(out)) as Hex;
  } finally {
    clearActiveRequest();
  }
}

function concatU8(...arr: Uint8Array[]): Uint8Array {
  let n = 0;
  for (const a of arr) n += a.length;
  const out = new Uint8Array(n);
  let off = 0;
  for (const a of arr) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

function tryDecodeUtf8(b: Uint8Array): string {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(b);
  } catch {
    return "[binary " + b.length + " bytes]";
  }
}
