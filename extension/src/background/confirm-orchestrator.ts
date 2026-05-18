// State of the in-flight request. The extension only allows ONE request
// at a time (one signing) — if a second one arrives while one is pending,
// it is rejected.
//
// IMPORTANT: unlike older versions, this module NO LONGER blocks the
// flow waiting for human confirmation in a popup. The REAL approval
// happens on the GBA (press A to sign, B to cancel). The extension
// popup only DISPLAYS the data and lets the user cancel the operation
// before the GBA responds.

import type { Address, Hex } from "../lib/types";

export type ConfirmRequest =
  | {
      kind: "send_tx" | "sign_tx";
      origin: string;
      address: Address;
      chainId: number;
      chainName: string;       // e.g. "BNB Smart Chain"
      nativeSymbol: string;    // e.g. "BNB"
      to: Address | null;
      valueHex: Hex;
      dataLen: number;
      dataHex: Hex;            // full calldata (used for decode + display)
      decodedFunc: string | null;  // e.g. "transfer(address,uint256)" if recognized
      decodedSummary: string | null; // e.g. "transfer 1.5 BNB to 0xabc..." if recognized
      signingHashHex: Hex;     // keccak256(rlp_envelope) — what the GBA signs
      nonceHex: Hex;
      gasHex: Hex;
      maxFeeHex?: Hex;
      tipHex?: Hex;
      gasPriceHex?: Hex;       // legacy
    }
  | {
      kind: "personal_sign";
      origin: string;
      address: Address;
      msgUtf8: string;
      msgHexLen: number;
      eip191HashHex: Hex;
    }
  | {
      kind: "typed_data";
      origin: string;
      address: Address;
      primaryType: string;
      domainName: string;
      chainId: number;
      humanText: string;
      domainSepHex: Hex;
      msgHashHex: Hex;
      digestHex: Hex;
    };

export interface ConfirmDecision {
  approved: boolean;
  error?: string;
}

interface ActiveRequest {
  request: ConfirmRequest;
  cancelFlag: { cancelled: boolean };
  startedAt: number;
}

let active: ActiveRequest | null = null;

/** Marks a request as active and tries to open the extension popup so
 *  the user can see it. Returns a cancelFlag the caller can poll (if
 *  the user presses Cancel in the popup, cancelFlag.cancelled becomes
 *  true). Does NOT block: the operation proceeds immediately.
 */
export function startActiveRequest(req: ConfirmRequest): { cancelled: { cancelled: boolean } } {
  if (active) {
    throw new Error("another operation is already in flight; wait for it to finish");
  }
  const cancelFlag = { cancelled: false };
  active = { request: req, cancelFlag, startedAt: Date.now() };
  setBadge(true);
  // Try to open the popup automatically. Only works if Chrome considers
  // there is a recent user gesture (sometimes when the dApp tab is
  // focused, it allows it). If it fails, the badge already signals that
  // something is pending.
  if (typeof chrome.action?.openPopup === "function") {
    try {
      chrome.action.openPopup().catch(() => {
        /* no gesture / not available: the badge is enough */
      });
    } catch {
      /* ignore */
    }
  }
  return { cancelled: cancelFlag };
}

/** Called at the end of the operation (whether or not the GBA responded).
 *  Clears the state to allow new requests. */
export function clearActiveRequest(): void {
  active = null;
  setBadge(false);
}

/** Called from the popup when the user presses "Cancel". */
export function cancelActiveRequest(): void {
  if (!active) return;
  active.cancelFlag.cancelled = true;
  // We do NOT clear `active` here: the provider-handler clears it when
  // the op truly finishes (the GBA can be slow; cancel is only a hint
  // so we abort the response when it eventually arrives).
}

/** For the popup: hand me the in-flight request (if any). */
export function getActiveRequest(): {
  request: ConfirmRequest;
  startedAt: number;
  cancelled: boolean;
} | null {
  if (!active) return null;
  return {
    request: active.request,
    startedAt: active.startedAt,
    cancelled: active.cancelFlag.cancelled,
  };
}

// Compat layer (older handlers still call these functions; we keep them
// as no-ops to avoid breaking imports during the refactor).
export function signalConfirmDecision(_d: ConfirmDecision): void {
  /* deprecated: the decision happens on the GBA */
}
export function getPendingConfirm(): ConfirmRequest | null {
  return active?.request ?? null;
}
export async function openConfirmWindow(req: ConfirmRequest): Promise<ConfirmDecision> {
  // Keeps the old signature so provider-handler doesn't break before we
  // migrate all callers. The new flow is: startActiveRequest + run op +
  // clearActiveRequest. Here we just simulate "approved" immediately.
  startActiveRequest(req);
  return { approved: true };
}

function setBadge(active: boolean) {
  try {
    chrome.action.setBadgeText({ text: active ? "1" : "" });
    chrome.action.setBadgeBackgroundColor({ color: "#6cf" });
  } catch {
    /* SW may not be ready at startup: ignore */
  }
}
