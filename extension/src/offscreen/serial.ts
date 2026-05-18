// Offscreen document that owns the WebSerial port and exposes high-level
// operations to the service worker.
//
// Messages (target = "offscreen-serial"):
//   { kind: "sb-open" }                  -> { ok, error? }
//   { kind: "sb-close" }                 -> { ok }
//   { kind: "sb-getAddress" }            -> { ok, addressHex? , error? }
//   { kind: "sb-signTx", rlpHex }        -> { ok, sigHex|null, error? }
//   { kind: "sb-personalSign", msgHex }  -> { ok, sigHex|null, error? }
//   { kind: "sb-typedData", ... }        -> { ok, sigHex|null, error? }
//   { kind: "sb-sendTxResult", ... }     -> { ok, error? }
//
// The offscreen keeps ONE global active session (currentSession). The SW
// must open, run ops, and close (preferably with a mutex on its own side).

export {};

import {
  PROTO_ACK,
  PROTO_ADDRSTART,
  PROTO_CANCEL,
  PROTO_DONE,
  PROTO_GET_ADDRESS,
  PROTO_GET_POLICY,
  PROTO_PERSONAL_SIGN,
  PROTO_POLICYSTART,
  PROTO_READY,
  PROTO_REJECT_CHAIN,
  PROTO_SIGSTART,
  PROTO_TX_META_MAX,
  PROTO_CONNECT_OK,
  PROTO_CONNECT_REQUEST,
  PROTO_HEARTBEAT,
  PROTO_TX_RLP,
  PROTO_TX_RLP_META,
  PROTO_TXRESULT,
  PROTO_TYPED_DATA,
  TXRESULT_BROADCAST_ERR,
  TXRESULT_BROADCAST_OK,
  TXRESULT_ERRMSG_MAX,
  TXRESULT_NO_BROADCAST,
} from "../background/protocol";
import { bytesToHex as bytesToHexRaw, hexToBytes } from "../lib/hex";

const bytesToHex = (b: Uint8Array) => "0x" + bytesToHexRaw(b);

const BAUD_RATE = 115200;
const READY_TIMEOUT_MS = 30000;
const STREAM_TIMEOUT_MS = 30000;

class GbaPortSession {
  private reader: ReadableStreamDefaultReader<Uint8Array>;
  private writer: WritableStreamDefaultWriter<Uint8Array>;
  private rxBuffer = new Uint8Array(0);

  constructor(private port: SerialPort) {
    if (!port.readable || !port.writable) {
      throw new Error("port is not open (readable/writable null)");
    }
    this.reader = port.readable.getReader();
    this.writer = port.writable.getWriter();
  }

  async close(): Promise<void> {
    try { this.reader.releaseLock(); } catch { /* ignore */ }
    try { this.writer.releaseLock(); } catch { /* ignore */ }
    try { await this.port.close(); } catch { /* ignore */ }
  }

  async write(bytes: Uint8Array): Promise<void> {
    await this.writer.write(bytes);
  }

  async read(n: number, timeoutMs: number): Promise<Uint8Array> {
    const deadline = Date.now() + timeoutMs;
    while (this.rxBuffer.length < n) {
      const remaining = deadline - Date.now();
      if (remaining <= 0) {
        throw new Error(`read(${n}) timeout (have ${this.rxBuffer.length} B in buffer)`);
      }
      const chunk = await readWithTimeout(this.reader, remaining);
      if (chunk === null) continue;
      const next = new Uint8Array(this.rxBuffer.length + chunk.length);
      next.set(this.rxBuffer, 0);
      next.set(chunk, this.rxBuffer.length);
      this.rxBuffer = next;
    }
    const out = this.rxBuffer.slice(0, n);
    this.rxBuffer = this.rxBuffer.slice(n);
    return out;
  }

  /** Reads and discards bytes until `settleMs` ms of silence. Used to
   *  swallow the "gba-signer bridge: ..." messages that the Pico's
   *  MicroPython prints on stdout during boot, plus any READY bytes
   *  buffered before our handshake starts. Equivalent to the `_drain()`
   *  in pc/serial_transport.py. */
  async drain(settleMs: number): Promise<void> {
    this.rxBuffer = new Uint8Array(0);
    while (true) {
      const chunk = await readWithTimeout(this.reader, settleMs);
      if (chunk === null || chunk.length === 0) return;
    }
  }
}

async function readWithTimeout(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  timeoutMs: number,
): Promise<Uint8Array | null> {
  let timer: number | undefined;
  const timeout = new Promise<null>((resolve) => {
    timer = self.setTimeout(() => resolve(null), timeoutMs);
  });
  const read = reader.read().then((r) => {
    if (timer !== undefined) clearTimeout(timer);
    return r.value ?? new Uint8Array(0);
  });
  return Promise.race([read, timeout]);
}

let currentSession: GbaPortSession | null = null;

// ---------------------------------------------------------------------------
// Local mutex: serializes ops AND heartbeats on the port.
//
// The SW also has a mutex (withGbaSession) but it only serializes what
// COMES IN through chrome.runtime.sendMessage. The heartbeat fires from
// an internal setInterval in the offscreen page and never crosses the SW,
// so we need our own lock — otherwise the heartbeat overlaps an in-flight
// signature and they fight over the port.
// ---------------------------------------------------------------------------

let lockChain: Promise<unknown> = Promise.resolve();

function withLock<T>(fn: () => Promise<T>): Promise<T> {
  const next = lockChain.then(fn, fn);
  lockChain = next.catch(() => undefined);
  return next;
}

// ---------------------------------------------------------------------------
// Fast heartbeat (5s) to detect cable unplug within a few seconds.
//
// chrome.alarms has a 30s minimum in MV3 prod, so we use a setInterval
// inside the offscreen page. The page stays alive as long as the SW
// keeps it open (we never call chrome.offscreen.closeDocument).
//
// The heartbeat does NOT fire if:
//   - no session is open (not connected yet, or already closed)
//   - another heartbeat is already queued (avoids backlog during a long signature)
//
// Errors are logged but NOT propagated: the heartbeat is best-effort.
// ---------------------------------------------------------------------------

const HEARTBEAT_INTERVAL_MS = 5000;
let heartbeatTimer: ReturnType<typeof setInterval> | null = null;
let heartbeatPending = false;

// After a successful tx signature, the GBA moves to "BROADCASTING..." and
// enters a loop that ONLY accepts PROTO_TXRESULT — it discards heartbeats.
// If a heartbeat slips between opSignTx and opSendTxResult the host waits
// 30s for a DONE that never arrives, which blocks sendTxResult after the
// signature. This window opens at the end of opSignTx (on a successful
// sig) and closes at the start of opSendTxResult (or by the 60s safety
// timeout).
let inTxResultWindow = false;
let txResultWindowTimer: ReturnType<typeof setTimeout> | null = null;

function enterTxResultWindow(): void {
  inTxResultWindow = true;
  if (txResultWindowTimer !== null) clearTimeout(txResultWindowTimer);
  // Safety: if the SW never calls sendTxResult (SW error, dApp aborts),
  // we re-enable heartbeats after 60s so the 'link:' indicator does not
  // get stuck on idle/NONE forever.
  txResultWindowTimer = setTimeout(() => {
    inTxResultWindow = false;
    txResultWindowTimer = null;
  }, 60_000);
}

function leaveTxResultWindow(): void {
  inTxResultWindow = false;
  if (txResultWindowTimer !== null) {
    clearTimeout(txResultWindowTimer);
    txResultWindowTimer = null;
  }
}

function startHeartbeat(): void {
  if (heartbeatTimer !== null) return;
  heartbeatTimer = setInterval(heartbeatTick, HEARTBEAT_INTERVAL_MS);
}

function stopHeartbeat(): void {
  if (heartbeatTimer === null) return;
  clearInterval(heartbeatTimer);
  heartbeatTimer = null;
}

async function heartbeatTick(): Promise<void> {
  if (!currentSession) return;       // session closed
  if (heartbeatPending) return;       // one already queued, don't pile up
  if (inTxResultWindow) return;       // GBA is waiting for TXRESULT, don't disturb
  heartbeatPending = true;
  try {
    await withLock(async () => {
      if (!currentSession) return;    // might have closed while waiting
      if (inTxResultWindow) return;   // might have entered while waiting for the lock
      try {
        await opHeartbeat();
      } catch (e) {
        // Silent: cable unplugged, Pico reset, GBA mid long signing...
        // The next tick will retry.
        console.debug("[gba-hb] failed:", e);
      }
    });
  } finally {
    heartbeatPending = false;
  }
}

async function openSession(): Promise<void> {
  if (currentSession) {
    // already open, leave it
    return;
  }
  if (!navigator.serial) {
    throw new Error("navigator.serial not available in this context");
  }
  const ports = await navigator.serial.getPorts();
  if (ports.length === 0) {
    throw new Error(
      "No authorized ports. Use popup -> Connect GBA and pick the Pico's serial port.",
    );
  }
  // If several are authorized, pick the first. The connect.html page
  // normally ensures only the Pico's port is authorized.
  const port = ports[0];
  if (!port.readable || !port.writable) {
    await port.open({ baudRate: BAUD_RATE });
  }
  // Some USB-CDC drivers toggle DTR on port open, which resets the
  // RP2040 and triggers its 2s rescue window. We try to drive DTR/RTS
  // low to reduce the chance of a reset (not every driver honours it,
  // but it doesn't hurt).
  try {
    await (port as any).setSignals({ dataTerminalReady: false, requestToSend: false });
  } catch {
    /* some backends don't support setSignals; ignore */
  }
  // Wait for the Pico USB-CDC to finish its reset boot (2s rescue
  // window + ~1s boot).
  await sleep(3000);

  currentSession = new GbaPortSession(port);

  // Drain MicroPython boot bytes ("gba-signer bridge: rescue window
  // 2s ...", "gba-signer bridge: starting bridge mode") and any READY
  // pulses, so the next read starts "clean". Same behaviour as
  // pc/serial_transport.py._drain().
  try {
    await currentSession.drain(200);
  } catch {
    /* if drain fails on some transient error, keep going */
  }

  // Once the session is up, start the fast (5s) heartbeat. It detects
  // cable unplug / extension closed within a few seconds.
  startHeartbeat();
}

async function closeSession(): Promise<void> {
  // Stop the heartbeat BEFORE closing the port: prevents an in-flight
  // tick from using a destroyed session.
  stopHeartbeat();
  // Any pending tx-result window is invalidated on close.
  leaveTxResultWindow();
  if (!currentSession) return;
  await currentSession.close();
  currentSession = null;
}

function requireSession(): GbaPortSession {
  if (!currentSession) {
    throw new Error("session not open; call sb-open first");
  }
  return currentSession;
}

// ---------------------------------------------------------------------------
// High-level protocol operations
// ---------------------------------------------------------------------------

async function waitFirstReady(s: GbaPortSession): Promise<void> {
  // Drain any residual bytes BEFORE we start. Covers:
  //  - READY pulses queued from the last op (>1 if the previous op was
  //    slow to read)
  //  - Leftover bytes from an op that failed mid-way (e.g. a heartbeat
  //    that threw a swallowed error and left a DONE in the buffer)
  //  - Bursts from the Pico after a USB-CDC reset
  //
  // 30 ms of "silence" = the GBA has not emitted the next READY pulse
  // yet (they come every 500 ms), so this ALWAYS eats all previous
  // pulses and clears leftovers. The next read waits for a fresh pulse.
  await s.drain(30);
  const b = await s.read(1, READY_TIMEOUT_MS);
  if (b[0] !== PROTO_READY) {
    throw new Error(`expected READY (0xAA), got 0x${b[0].toString(16).padStart(2, "0")}`);
  }
}

async function drainUntil(s: GbaPortSession, markers: number[]): Promise<number> {
  for (let i = 0; i < 32; i++) {
    const b = await s.read(1, STREAM_TIMEOUT_MS);
    if (b[0] === PROTO_READY) continue;
    if (markers.includes(b[0])) return b[0];
    throw new Error(`unexpected marker 0x${b[0].toString(16).padStart(2, "0")}`);
  }
  throw new Error("flooded with READY: no valid marker arrived");
}

async function opGetAddress(): Promise<Uint8Array> {
  const s = requireSession();
  await waitFirstReady(s);
  await s.write(new Uint8Array([PROTO_ACK]));
  await sleep(50);
  await s.write(new Uint8Array([PROTO_GET_ADDRESS]));
  const marker = await drainUntil(s, [PROTO_ADDRSTART, PROTO_CANCEL]);
  if (marker === PROTO_CANCEL) {
    await s.read(1, STREAM_TIMEOUT_MS); // DONE
    throw new Error("GBA cancelled get_address");
  }
  const addr = await s.read(20, STREAM_TIMEOUT_MS);
  const done = await s.read(1, STREAM_TIMEOUT_MS);
  if (done[0] !== PROTO_DONE) {
    throw new Error(`expected DONE, got 0x${done[0].toString(16)}`);
  }
  return addr;
}

/** Outcome of a tx-sign request to the GBA. The GBA can:
 *   - sign -> { kind: "sig", sig }
 *   - cancel (B button) -> { kind: "cancel" }
 *   - reject due to chain-lock mismatch -> { kind: "reject_chain", expected, got }
 *
 * This used to be `Uint8Array | null` (sig|cancel) and chain rejection got
 * conflated with user cancellation, which is semantically different: the
 * user NEVER saw the confirmation screen because the GBA blocked it.
 */
export type SignTxOutcome =
  | { kind: "sig"; sig: Uint8Array }
  | { kind: "cancel" }
  | { kind: "reject_chain"; expected: number; got: number };

async function opSignTx(
  rlp: Uint8Array,
  meta?: Uint8Array,
): Promise<SignTxOutcome> {
  const s = requireSession();
  await waitFirstReady(s);
  await s.write(new Uint8Array([PROTO_ACK]));
  await sleep(50);

  // If we have meta (non-empty and within the cap), use the v6 opcode
  // PROTO_TX_RLP_META with a trailing block. Otherwise the classic
  // PROTO_TX_RLP with no meta — the GBA can't tell the difference.
  const useMeta = meta !== undefined && meta.length > 0;
  if (useMeta && meta!.length > PROTO_TX_META_MAX) {
    throw new Error(`meta size ${meta!.length} > ${PROTO_TX_META_MAX}`);
  }

  const header = new Uint8Array(5);
  header[0] = useMeta ? PROTO_TX_RLP_META : PROTO_TX_RLP;
  const len = rlp.length;
  header[1] = (len >>> 24) & 0xff;
  header[2] = (len >>> 16) & 0xff;
  header[3] = (len >>> 8) & 0xff;
  header[4] = len & 0xff;
  await s.write(header);
  await s.write(rlp);

  if (useMeta) {
    const mlen = meta!.length;
    const metaHeader = new Uint8Array([(mlen >>> 8) & 0xff, mlen & 0xff]);
    await s.write(metaHeader);
    await s.write(meta!);
  }
  const marker = await drainUntil(s, [PROTO_SIGSTART, PROTO_CANCEL, PROTO_REJECT_CHAIN]);
  if (marker === PROTO_REJECT_CHAIN) {
    // 4B expected (BE) + 4B got (BE) + DONE
    const expected = await readU32Be(s);
    const got = await readU32Be(s);
    const done = await s.read(1, STREAM_TIMEOUT_MS);
    if (done[0] !== PROTO_DONE) {
      throw new Error(
        `expected DONE after REJECT_CHAIN, got 0x${done[0].toString(16)}`,
      );
    }
    return { kind: "reject_chain", expected, got };
  }
  if (marker === PROTO_CANCEL) {
    await s.read(1, STREAM_TIMEOUT_MS);
    return { kind: "cancel" };
  }
  const sig = await s.read(65, STREAM_TIMEOUT_MS);
  const done = await s.read(1, STREAM_TIMEOUT_MS);
  if (done[0] !== PROTO_DONE) {
    throw new Error(`expected DONE after sig, got 0x${done[0].toString(16)}`);
  }
  // The GBA has just moved to "BROADCASTING..." (await_and_show_tx_result).
  // In that state it only reads PROTO_TXRESULT; any heartbeat slipped
  // between now and opSendTxResult would never be answered and block us
  // for 30s.
  enterTxResultWindow();
  return { kind: "sig", sig };
}

async function readU32Be(s: GbaPortSession): Promise<number> {
  const b = await s.read(4, STREAM_TIMEOUT_MS);
  return (b[0] * 0x1000000) + ((b[1] << 16) | (b[2] << 8) | b[3]);
}

async function opGetPolicy(): Promise<number> {
  const s = requireSession();
  await waitFirstReady(s);
  await s.write(new Uint8Array([PROTO_ACK]));
  await sleep(50);
  await s.write(new Uint8Array([PROTO_GET_POLICY]));
  const marker = await drainUntil(s, [PROTO_POLICYSTART, PROTO_CANCEL]);
  if (marker === PROTO_CANCEL) {
    await s.read(1, STREAM_TIMEOUT_MS);
    throw new Error("GBA cancelled get_policy");
  }
  const chainId = await readU32Be(s);
  const done = await s.read(1, STREAM_TIMEOUT_MS);
  if (done[0] !== PROTO_DONE) {
    throw new Error(`expected DONE after policy, got 0x${done[0].toString(16)}`);
  }
  return chainId;
}

/** Connect request: shows a screen on the GBA with the dApp's origin and
 *  waits for A/B. Returns true if the user approves (CONNECT_OK), false
 *  if they deny (CANCEL). The caller persists the decision in
 *  chrome.storage. */
async function opConnectRequest(origin: string): Promise<boolean> {
  const s = requireSession();
  await waitFirstReady(s);
  await s.write(new Uint8Array([PROTO_ACK]));
  await sleep(50);
  await s.write(new Uint8Array([PROTO_CONNECT_REQUEST]));

  // payload: 2B BE len + ASCII bytes
  const bytes = new TextEncoder().encode(origin);
  if (bytes.length > 96) {
    throw new Error(`origin too long (${bytes.length} > 96)`);
  }
  const lenBe = new Uint8Array([(bytes.length >>> 8) & 0xff, bytes.length & 0xff]);
  await s.write(lenBe);
  await s.write(bytes);

  // The GBA replies with CONNECT_OK (approved) or CANCEL (denied),
  // followed by DONE. We drain residual READY pulses from the polling
  // cycle.
  const marker = await drainUntil(s, [PROTO_CONNECT_OK, PROTO_CANCEL]);
  const done = await s.read(1, STREAM_TIMEOUT_MS);
  if (done[0] !== PROTO_DONE) {
    throw new Error(`expected DONE after connect, got 0x${done[0].toString(16)}`);
  }
  return marker === PROTO_CONNECT_OK;
}

/** Heartbeat: ACK + 0xC4 + DONE. The GBA only uses it to refresh the
 *  'link:' indicator. No payload. */
async function opHeartbeat(): Promise<void> {
  const s = requireSession();
  await waitFirstReady(s);
  await s.write(new Uint8Array([PROTO_ACK]));
  await sleep(50);
  await s.write(new Uint8Array([PROTO_HEARTBEAT]));
  const done = await s.read(1, STREAM_TIMEOUT_MS);
  if (done[0] !== PROTO_DONE) {
    throw new Error(`expected DONE after heartbeat, got 0x${done[0].toString(16)}`);
  }
}

async function opPersonalSign(msg: Uint8Array): Promise<Uint8Array | null> {
  const s = requireSession();
  await waitFirstReady(s);
  await s.write(new Uint8Array([PROTO_ACK]));
  await sleep(50);
  const header = new Uint8Array(5);
  header[0] = PROTO_PERSONAL_SIGN;
  header[1] = (msg.length >>> 24) & 0xff;
  header[2] = (msg.length >>> 16) & 0xff;
  header[3] = (msg.length >>> 8) & 0xff;
  header[4] = msg.length & 0xff;
  await s.write(header);
  await s.write(msg);
  const marker = await drainUntil(s, [PROTO_SIGSTART, PROTO_CANCEL]);
  if (marker === PROTO_CANCEL) {
    await s.read(1, STREAM_TIMEOUT_MS);
    return null;
  }
  const sig = await s.read(65, STREAM_TIMEOUT_MS);
  const done = await s.read(1, STREAM_TIMEOUT_MS);
  if (done[0] !== PROTO_DONE) {
    throw new Error(`expected DONE, got 0x${done[0].toString(16)}`);
  }
  return sig;
}

async function opTypedData(
  domainSep: Uint8Array,
  messageHash: Uint8Array,
  humanText: Uint8Array,
): Promise<Uint8Array | null> {
  const s = requireSession();
  if (domainSep.length !== 32 || messageHash.length !== 32) {
    throw new Error("domainSep and messageHash must be 32 bytes");
  }
  await waitFirstReady(s);
  await s.write(new Uint8Array([PROTO_ACK]));
  await sleep(50);
  const head = new Uint8Array(1 + 32 + 32 + 4);
  head[0] = PROTO_TYPED_DATA;
  head.set(domainSep, 1);
  head.set(messageHash, 1 + 32);
  const len = humanText.length;
  head[1 + 64 + 0] = (len >>> 24) & 0xff;
  head[1 + 64 + 1] = (len >>> 16) & 0xff;
  head[1 + 64 + 2] = (len >>> 8) & 0xff;
  head[1 + 64 + 3] = len & 0xff;
  await s.write(head);
  await s.write(humanText);
  const marker = await drainUntil(s, [PROTO_SIGSTART, PROTO_CANCEL]);
  if (marker === PROTO_CANCEL) {
    await s.read(1, STREAM_TIMEOUT_MS);
    return null;
  }
  const sig = await s.read(65, STREAM_TIMEOUT_MS);
  const done = await s.read(1, STREAM_TIMEOUT_MS);
  if (done[0] !== PROTO_DONE) {
    throw new Error(`expected DONE, got 0x${done[0].toString(16)}`);
  }
  return sig;
}

async function opSendTxResult(
  status: number,
  txhash?: Uint8Array,
  errmsg?: string,
): Promise<void> {
  const s = requireSession();
  // Close the heartbeat-suppression window: after this op the GBA
  // returns to the normal awaiting-tx loop and heartbeats are safe again.
  leaveTxResultWindow();
  let payload: Uint8Array;
  if (status === TXRESULT_BROADCAST_OK || status === TXRESULT_NO_BROADCAST) {
    if (!txhash || txhash.length !== 32) {
      throw new Error("status OK requires a 32B txhash");
    }
    payload = new Uint8Array(1 + 32);
    payload[0] = status;
    payload.set(txhash, 1);
  } else if (status === TXRESULT_BROADCAST_ERR) {
    const enc = new TextEncoder().encode(errmsg ?? "");
    const truncated = enc.slice(0, TXRESULT_ERRMSG_MAX);
    payload = new Uint8Array(1 + 1 + truncated.length);
    payload[0] = status;
    payload[1] = truncated.length;
    payload.set(truncated, 2);
  } else {
    throw new Error(`unknown status ${status}`);
  }
  await sleep(50);
  await s.write(new Uint8Array([PROTO_TXRESULT]));
  await sleep(25);
  await s.write(payload);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ---------------------------------------------------------------------------
// Message listener
// ---------------------------------------------------------------------------

interface SbMsg {
  target?: string;
  kind: string;
  [k: string]: unknown;
}

chrome.runtime.onMessage.addListener((msg: SbMsg, _sender, sendResponse) => {
  if (msg?.target !== "offscreen-serial") return; // not ours
  (async () => {
    try {
      // Open/close handle their own lifecycle (heartbeat start/stop). The
      // rest is serialized with withLock so heartbeats and operations
      // don't step on each other (the SW already serializes via its own
      // mutex, but we keep defence in depth).
      switch (msg.kind) {
        case "sb-open": {
          await openSession();
          sendResponse({ ok: true });
          break;
        }
        case "sb-close": {
          await withLock(closeSession);
          sendResponse({ ok: true });
          break;
        }
        case "sb-getAddress": {
          const addr = await withLock(opGetAddress);
          sendResponse({ ok: true, addressHex: bytesToHex(addr) });
          break;
        }
        case "sb-signTx": {
          const rlp = hexToBytes(String(msg.rlpHex));
          const meta = msg.metaHex
            ? hexToBytes(String(msg.metaHex))
            : undefined;
          const out = await withLock(() => opSignTx(rlp, meta));
          if (out.kind === "sig") {
            sendResponse({ ok: true, signTx: { kind: "sig", sigHex: bytesToHex(out.sig) } });
          } else if (out.kind === "cancel") {
            sendResponse({ ok: true, signTx: { kind: "cancel" } });
          } else {
            sendResponse({
              ok: true,
              signTx: { kind: "reject_chain", expected: out.expected, got: out.got },
            });
          }
          break;
        }
        case "sb-getPolicy": {
          const chainId = await withLock(opGetPolicy);
          sendResponse({ ok: true, chainId });
          break;
        }
        case "sb-heartbeat": {
          await withLock(opHeartbeat);
          sendResponse({ ok: true });
          break;
        }
        case "sb-connectRequest": {
          const approved = await withLock(() => opConnectRequest(String(msg.origin)));
          sendResponse({ ok: true, approved });
          break;
        }
        case "sb-personalSign": {
          const m = hexToBytes(String(msg.msgHex));
          const sig = await withLock(() => opPersonalSign(m));
          sendResponse({ ok: true, sigHex: sig ? bytesToHex(sig) : null });
          break;
        }
        case "sb-typedData": {
          const domainSep = hexToBytes(String(msg.domainSepHex));
          const messageHash = hexToBytes(String(msg.messageHashHex));
          const humanText = hexToBytes(String(msg.humanTextHex));
          const sig = await withLock(() => opTypedData(domainSep, messageHash, humanText));
          sendResponse({ ok: true, sigHex: sig ? bytesToHex(sig) : null });
          break;
        }
        case "sb-sendTxResult": {
          const status = Number(msg.status);
          const txhash = msg.txhashHex ? hexToBytes(String(msg.txhashHex)) : undefined;
          const errmsg = msg.errmsg ? String(msg.errmsg) : undefined;
          await withLock(() => opSendTxResult(status, txhash, errmsg));
          sendResponse({ ok: true });
          break;
        }
        default:
          sendResponse({ ok: false, error: `unknown kind: ${msg.kind}` });
      }
    } catch (e) {
      sendResponse({
        ok: false,
        error: e instanceof Error ? e.message : String(e),
      });
    }
  })();
  return true; // channel kept open async
});
