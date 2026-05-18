// Helpers shared by every method handler. Keeping them here (and not in
// provider-handler.ts) breaks import cycles between methods/*.

import type { Hex } from "../../lib/types";
import { getAddressBytes } from "../session";
import { RpcError } from "../rpc-passthrough";

export async function mustAddressBytes(): Promise<Uint8Array> {
  const a = await getAddressBytes();
  if (!a) throw new RpcError(4100, "Wallet disconnected");
  return a;
}

export async function assertConnected(_origin: string): Promise<void> {
  const a = await getAddressBytes();
  if (!a) throw new RpcError(4100, "Wallet disconnected");
}

export function parseHexBigInt(h: Hex | string): bigint {
  const s = h.startsWith("0x") || h.startsWith("0X") ? h.slice(2) : h;
  return s.length === 0 ? 0n : BigInt("0x" + s);
}

export function parseChainId(c: Hex | string | number): number {
  if (typeof c === "number") return c;
  const s = String(c);
  if (s.startsWith("0x") || s.startsWith("0X")) return parseInt(s, 16);
  return parseInt(s, 10);
}
