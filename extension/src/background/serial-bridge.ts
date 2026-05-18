// Bridge between the MV3 service worker and the offscreen document that
// holds navigator.serial access.
//
// The SW cannot use WebSerial. What this bridge does is:
//   1) Make sure the offscreen document is loaded.
//   2) Forward GBA operation messages to it.
//   3) Serialize access (mutex) so commands on the same port do not
//      overlap.
//
// The offscreen owns ONE active port (no multi-session support). The
// bridge opens and closes per op, the same way transport.ts used to.

import { TXRESULT_BROADCAST_ERR, TXRESULT_BROADCAST_OK, TXRESULT_NO_BROADCAST } from "./protocol";
import { bytesToHex as bytesToHexRaw, hexToBytes } from "../lib/hex";

const bytesToHex = (b: Uint8Array) => "0x" + bytesToHexRaw(b);

const OFFSCREEN_URL = "src/offscreen/serial.html";

// Reason: we use WORKERS because WebSerial does not match any official
// reason exactly, but offscreen documents are not limited to the APIs
// declared in `reasons` (it is informative + a hint to Chrome for
// lifecycle management).
const OFFSCREEN_REASON: chrome.offscreen.Reason = "WORKERS" as chrome.offscreen.Reason;

let creating: Promise<void> | null = null;

async function ensureOffscreen(): Promise<void> {
  // Different APIs across Chrome versions. Check whether it already exists.
  if (await hasOffscreen()) return;
  if (creating) {
    await creating;
    return;
  }
  creating = chrome.offscreen
    .createDocument({
      url: OFFSCREEN_URL,
      reasons: [OFFSCREEN_REASON],
      justification:
        "Access to navigator.serial to talk to Coldpakku (not available in MV3 service workers).",
    })
    .catch((e) => {
      // If it already existed (race), Chrome throws; we ignore that.
      if (!String(e).includes("Only a single offscreen document")) throw e;
    })
    .finally(() => {
      creating = null;
    });
  await creating;
}

async function hasOffscreen(): Promise<boolean> {
  // chrome.offscreen.hasDocument() exists but is flaky on some versions.
  // More robust: use runtime.getContexts. The @types/chrome typings lag
  // behind the real API (ContextType strings don't include
  // "OFFSCREEN_DOCUMENT"), so we cast to any.
  const rt = chrome.runtime as any;
  if (typeof rt.getContexts === "function") {
    const contexts = await rt.getContexts({
      contextTypes: ["OFFSCREEN_DOCUMENT"],
      documentUrls: [chrome.runtime.getURL(OFFSCREEN_URL)],
    });
    return Array.isArray(contexts) && contexts.length > 0;
  }
  const off = chrome.offscreen as any;
  if (typeof off.hasDocument === "function") {
    return !!(await off.hasDocument());
  }
  return false;
}

interface SbResponse {
  ok: boolean;
  error?: string;
  addressHex?: string;
  sigHex?: string | null;
  chainId?: number;
  approved?: boolean;
  signTx?:
    | { kind: "sig"; sigHex: string }
    | { kind: "cancel" }
    | { kind: "reject_chain"; expected: number; got: number };
}

/** Public outcome consumed by the provider-handler. Same shape as the
 *  offscreen one, but with bytes already deserialized. */
export type GbaSignTxOutcome =
  | { kind: "sig"; sig: Uint8Array }
  | { kind: "cancel" }
  | { kind: "reject_chain"; expected: number; got: number };

async function callOffscreen(payload: Record<string, unknown>): Promise<SbResponse> {
  await ensureOffscreen();
  const msg = { target: "offscreen-serial", ...payload };
  const r = (await chrome.runtime.sendMessage(msg)) as SbResponse | undefined;
  if (!r) throw new Error("offscreen did not reply (message dropped)");
  if (!r.ok) throw new Error(r.error ?? "offscreen error");
  return r;
}

// ---------------------------------------------------------------------------
// Mutex: only one op-group at a time on the port.
// ---------------------------------------------------------------------------

let chain: Promise<unknown> = Promise.resolve();

function withLock<T>(fn: () => Promise<T>): Promise<T> {
  const next = chain.then(fn, fn);
  // Swallow chain errors so the queue does not get "poisoned".
  chain = next.catch(() => undefined);
  return next;
}

// ---------------------------------------------------------------------------
// Public API: one GBA session = open + ops + close.
// ---------------------------------------------------------------------------

export async function withGbaSession<T>(
  fn: (s: BridgeSession) => Promise<T>,
): Promise<T> {
  // The offscreen keeps the session open between ops to:
  //   1. Avoid the 3s Pico USB-CDC settle delay on every op
  //   2. Keep the 5s heartbeat alive (which lives in the offscreen)
  //
  // The SW still serializes ops with withLock; sb-open is idempotent
  // (no-op if a session is already open). We never call sb-close: the
  // session is only closed when the offscreen page is destroyed
  // (extension reload) or on an explicit popup disconnect.
  return withLock(async () => {
    await callOffscreen({ kind: "sb-open" });
    return await fn(new BridgeSession());
  });
}

export class BridgeSession {
  async getAddress(): Promise<Uint8Array> {
    const r = await callOffscreen({ kind: "sb-getAddress" });
    if (!r.addressHex) throw new Error("offscreen returned no addressHex");
    return hexToBytes(r.addressHex);
  }

  async signTx(
    rlp: Uint8Array,
    meta?: Uint8Array,
  ): Promise<GbaSignTxOutcome> {
    const r = await callOffscreen({
      kind: "sb-signTx",
      rlpHex: bytesToHex(rlp),
      metaHex: meta && meta.length > 0 ? bytesToHex(meta) : undefined,
    });
    const out = r.signTx;
    if (!out) {
      // Old host (no signTx struct) — fall back to the old shape
      return r.sigHex ? { kind: "sig", sig: hexToBytes(r.sigHex) } : { kind: "cancel" };
    }
    if (out.kind === "sig") return { kind: "sig", sig: hexToBytes(out.sigHex) };
    if (out.kind === "cancel") return { kind: "cancel" };
    return { kind: "reject_chain", expected: out.expected, got: out.got };
  }

  /** Heartbeat: makes the GBA mark "host seen" and stay in link: ACTIVE.
   *  No payload, no error if the GBA does not reply — the caller must
   *  tolerate failures to avoid breaking the rest of the flow. */
  async heartbeat(): Promise<void> {
    await callOffscreen({ kind: "sb-heartbeat" });
  }

  /** Asks the user on the GBA to approve a dApp's access to the address.
   *  Returns true on A (allow), false on B (deny). The caller must
   *  persist the decision in chrome.storage so we do not ask again on
   *  later visits from the same origin. */
  async requestConnect(origin: string): Promise<boolean> {
    const r = await callOffscreen({ kind: "sb-connectRequest", origin });
    return !!r.approved;
  }

  /** Reads the network locked on the GBA (chain_id, 0 = ANY). Cache it
   *  in the service worker so the popup badge can show it. */
  async getPolicy(): Promise<number> {
    const r = await callOffscreen({ kind: "sb-getPolicy" });
    if (typeof r.chainId !== "number") {
      throw new Error("offscreen returned no chainId in getPolicy");
    }
    return r.chainId;
  }

  async personalSign(msg: Uint8Array): Promise<Uint8Array | null> {
    const r = await callOffscreen({
      kind: "sb-personalSign",
      msgHex: bytesToHex(msg),
    });
    return r.sigHex ? hexToBytes(r.sigHex) : null;
  }

  async typedData(
    domainSep: Uint8Array,
    messageHash: Uint8Array,
    humanText: Uint8Array,
  ): Promise<Uint8Array | null> {
    const r = await callOffscreen({
      kind: "sb-typedData",
      domainSepHex: bytesToHex(domainSep),
      messageHashHex: bytesToHex(messageHash),
      humanTextHex: bytesToHex(humanText),
    });
    return r.sigHex ? hexToBytes(r.sigHex) : null;
  }

  async sendTxResult(
    status: number,
    txhash?: Uint8Array,
    errmsg?: string,
  ): Promise<void> {
    if (
      status !== TXRESULT_BROADCAST_OK &&
      status !== TXRESULT_BROADCAST_ERR &&
      status !== TXRESULT_NO_BROADCAST
    ) {
      throw new Error(`invalid status ${status}`);
    }
    await callOffscreen({
      kind: "sb-sendTxResult",
      status,
      txhashHex: txhash ? bytesToHex(txhash) : undefined,
      errmsg,
    });
  }
}

