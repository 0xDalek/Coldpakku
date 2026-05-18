// MV3 service worker entry. Receives:
//   - messages from the content-script (RPC requests from the dApp)
//   - messages from the popup (connect, disconnect, switch chain)
//   - messages from the confirm popup (A/B decision)
//
// Uses chrome.runtime.onMessage as the bus.

import { handleRpc, connectAndCacheAddress, refreshGbaPolicy } from "./provider-handler";
import {
  cancelActiveRequest,
  getActiveRequest,
} from "./confirm-orchestrator";
import {
  clearAddress,
  getActiveNetwork,
  getGbaPolicyChainId,
  loadState,
} from "./session";

interface MsgFromContent {
  kind: "gba-rpc";
  origin: string;
  request: { method: string; params?: unknown };
}
interface MsgFromPopup {
  kind:
    | "popup-connect"
    | "popup-disconnect"
    | "popup-state"
    | "popup-active-request"
    | "popup-cancel-active"
    | "popup-refresh-gba-policy";
  payload?: any;
}
interface MsgFromConfirm {
  kind: "confirm-fetch" | "confirm-decision";
  payload?: any;
}

type AnyMsg = MsgFromContent | MsgFromPopup | MsgFromConfirm;

// ============================================================================
// GBA chain-lock policy refresh
// ============================================================================
//
// The GBA is the network authority. The extension learns the chain lock on:
//   - popup-state (opportunistic refresh if cache > 10s)
//   - popup-refresh-gba-policy ("refresh" button in the popup)
//   - every signing op (the offscreen session reads policy on open if needed)
//   - after a REJECT_CHAIN (the GBA just revealed its real lock)
//
// We used to have a chrome.alarms every 30s to "push" chainChanged to
// idle dApps. We removed it to minimise permissions and keep things
// simple; the cost is that dApps with the tab open but unused can lag
// behind on chain switches until the user interacts. Acceptable.

chrome.runtime.onMessage.addListener((msg: any, sender, sendResponse) => {
  // Messages targeted at the offscreen document MUST NOT be handled here;
  // if we reply before the offscreen does, we clobber the real reply.
  if (msg?.target === "offscreen-serial") return false;
  // Broadcast events (gba-event) are emitted by the SW for popup/content;
  // the SW MUST NOT reply to them (no request, no sendResponse expected).
  if (msg?.kind === "gba-event") return false;
  // The handler is async; return true so Chrome keeps the channel open
  // until we call sendResponse.
  (async () => {
    try {
      switch ((msg as AnyMsg).kind) {
        case "gba-rpc": {
          const origin = sender.tab?.url ? new URL(sender.tab.url).origin : msg.origin;
          const result = await handleRpc(origin, msg.request as any);
          sendResponse(result);
          break;
        }
        case "popup-connect": {
          const r = await connectAndCacheAddress();
          sendResponse({ ok: true, address: r.address, policyChainId: r.policyChainId });
          break;
        }
        case "popup-refresh-gba-policy": {
          const chainId = await refreshGbaPolicy();
          sendResponse({ ok: true, chainId });
          break;
        }
        case "popup-disconnect": {
          await clearAddress();
          sendResponse({ ok: true });
          break;
        }
        case "popup-state": {
          const s = await loadState();
          // If the cache is stale (>10s), kick off an opportunistic
          // refresh so the network badge is current. We do NOT wait for
          // it — the popup updates itself via gbaPolicyChanged /
          // chainChanged events if anything changes.
          if (s.addressChecksum && (Date.now() - s.gbaPolicyTs) > 10_000) {
            refreshGbaPolicy().catch(() => {});
          }
          const net = await getActiveNetwork();   /* derived from gbaPolicyChainId */
          const gbaPolicyChainId = await getGbaPolicyChainId();
          sendResponse({
            ok: true,
            address: s.addressChecksum,
            // The active network is ALWAYS the GBA's. The extension has
            // no separate network of its own, and there is no dropdown
            // that could change it.
            chainId: net.chainId,
            chainIdHex: net.chainIdHex,
            chainName: net.name,
            nativeSymbol: net.nativeCurrency.symbol,
            gbaPolicyChainId,
            gbaPolicyKnown: gbaPolicyChainId !== 0,
          });
          break;
        }
        case "popup-active-request": {
          // The popup asks whether there is an in-flight request to display.
          sendResponse({ ok: true, active: getActiveRequest() });
          break;
        }
        case "popup-cancel-active": {
          cancelActiveRequest();
          sendResponse({ ok: true });
          break;
        }
        default:
          sendResponse({ ok: false, error: "unknown kind" });
      }
    } catch (e) {
      sendResponse({
        ok: false,
        error: e instanceof Error ? e.message : String(e),
      });
    }
  })();
  return true;
});
