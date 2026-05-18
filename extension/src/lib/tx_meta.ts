// Informational metadata that travels with the tx in PROTO_TX_RLP_META.
//
// Every field is optional. The GBA renders them as "host says X" — they
// are UX hints, NOT crypto-verifiable. Equivalent to TxMeta in
// pc/protocol.py and tx_meta in src/link/tx_meta.{c,h}.

import {
  META_NAME_MAX,
  META_ORIGIN_MAX,
  META_SYMBOL_MAX,
  META_TYPE_ORIGIN,
  META_TYPE_TO_DECIMALS,
  META_TYPE_TO_NAME,
  META_TYPE_TO_SYMBOL,
  PROTO_TX_META_MAX,
} from "../background/protocol";

export interface TxMeta {
  origin?: string;       // "app.uniswap.org" (no protocol; host trimmed of https://)
  toName?: string;       // "WETH9", "Uniswap V3 Router"
  toSymbol?: string;     // "WETH", "USDC", "WBNB"
  toDecimals?: number;   // 0..77
}

/** Sanitises a string to visible ASCII (0x20..0x7E), replacing anything
 *  else with '?'. Truncates to `maxLen` chars (not bytes — assumes
 *  ASCII; emojis don't survive sanitisation as their original byte). */
function sanitizeAscii(s: string, maxLen: number): Uint8Array {
  const out: number[] = [];
  for (let i = 0; i < s.length && out.length < maxLen; i++) {
    const o = s.charCodeAt(i);
    out.push(o >= 0x20 && o < 0x7f ? o : 0x3f /* '?' */);
  }
  return new Uint8Array(out);
}

/** Encodes the present fields as TLV [type:1B + len:1B + value:N]. */
export function encodeTxMetaTlv(m: TxMeta): Uint8Array {
  const parts: Uint8Array[] = [];

  const pushStr = (type: number, value: string | undefined, max: number) => {
    if (value === undefined) return;
    const v = sanitizeAscii(value, max);
    parts.push(new Uint8Array([type, v.length]), v);
  };

  pushStr(META_TYPE_ORIGIN, m.origin, META_ORIGIN_MAX);
  pushStr(META_TYPE_TO_NAME, m.toName, META_NAME_MAX);
  pushStr(META_TYPE_TO_SYMBOL, m.toSymbol, META_SYMBOL_MAX);

  if (m.toDecimals !== undefined) {
    const d = Math.trunc(m.toDecimals);
    if (d >= 0 && d <= 77) {
      parts.push(new Uint8Array([META_TYPE_TO_DECIMALS, 1, d]));
    }
  }

  let total = 0;
  for (const p of parts) total += p.length;
  if (total > PROTO_TX_META_MAX) {
    throw new Error(
      `meta TLV size ${total} > PROTO_TX_META_MAX=${PROTO_TX_META_MAX}`,
    );
  }
  const merged = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    merged.set(p, off);
    off += p.length;
  }
  return merged;
}

/** True if every field is undefined. */
export function isEmptyTxMeta(m: TxMeta | undefined): boolean {
  if (!m) return true;
  return m.origin === undefined && m.toName === undefined
      && m.toSymbol === undefined && m.toDecimals === undefined;
}
