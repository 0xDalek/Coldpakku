// Content script: runs in each page's ISOLATED world. Its only job is
// to relay between:
//   - the injected-provider (which lives in the MAIN world via
//     content_scripts)
//   - the service-worker (which has access to chrome.* and WebSerial)
//
// injected<->content uses window.postMessage on a "gba-signer:*"
// namespaced channel. content<->SW uses chrome.runtime.

export {};

const NS_REQ = "gba-signer:request";
const NS_RES = "gba-signer:response";
const NS_EVT = "gba-signer:event";

// Forward requests injected -> SW
window.addEventListener("message", (ev: MessageEvent) => {
  if (ev.source !== window) return;
  const data = ev.data;
  if (!data || data.namespace !== NS_REQ) return;
  const { id, request } = data;

  // If the extension has been reloaded/updated, the content-script
  // context is invalidated and chrome.runtime throws. Catch it and
  // return a valid JSON-RPC error so the dApp doesn't hang showing
  // "Please confirm in wallet...".
  if (!chrome.runtime?.id) {
    sendErrorBack(id, "GBA Signer: extension reload pending. Reload this tab (F5).");
    return;
  }
  try {
    chrome.runtime.sendMessage(
      { kind: "gba-rpc", origin: window.location.origin, request },
      (response) => {
        if (chrome.runtime.lastError) {
          sendErrorBack(
            id,
            `GBA Signer SW error: ${chrome.runtime.lastError.message ?? "unknown"}. Reload this tab (F5).`,
          );
          return;
        }
        window.postMessage({ namespace: NS_RES, id, response }, "*");
      },
    );
  } catch (e) {
    sendErrorBack(
      id,
      `GBA Signer transport error: ${e instanceof Error ? e.message : String(e)}. Reload this tab (F5).`,
    );
  }
});

function sendErrorBack(id: number, message: string) {
  window.postMessage(
    {
      namespace: NS_RES,
      id,
      response: { error: { code: -32603, message } },
    },
    "*",
  );
}

// Forward events SW -> injected (accountsChanged, chainChanged).
chrome.runtime.onMessage.addListener((msg) => {
  if (!msg || msg.kind !== "gba-event") return;
  window.postMessage(
    {
      namespace: NS_EVT,
      ev: msg.ev,
    },
    "*",
  );
});
