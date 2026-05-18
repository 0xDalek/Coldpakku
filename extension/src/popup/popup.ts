// Popup UI: connect / disconnect / switch network.
// The critical bit is "Connect": for navigator.serial.requestPort() to
// work we need a user-gesture context (a click), so the call has to be
// made HERE in the popup, NOT in the service worker.

export {};

interface PopupState {
  ok: boolean;
  address: string | null;
  // Active chain = GBA's chain (the GBA is the authority). These fields
  // describe that network. If the GBA is not connected/cached,
  // gbaPolicyKnown is false and we show "no lock yet" on the badge.
  chainId: number;
  chainIdHex: string;
  chainName: string;
  nativeSymbol: string;
  gbaPolicyChainId: number;
  gbaPolicyKnown: boolean;
}

interface ActiveRequestInfo {
  request: any;
  startedAt: number;
  cancelled: boolean;
}

const $ = (id: string) => document.getElementById(id) as HTMLElement;

let pollTimer: number | undefined;

async function refresh() {
  // If there is an active request, show it above everything else: it's
  // what the user wants to see right now.
  const ar = await chrome.runtime.sendMessage({ kind: "popup-active-request" });
  const active: ActiveRequestInfo | null = ar?.active ?? null;
  if (active) {
    showPending(active);
    schedulePoll();
    return;
  }

  const state: PopupState = await chrome.runtime.sendMessage({ kind: "popup-state" });
  if (state.address) {
    showConnected(state);
  } else {
    showDisconnected();
  }
}

function schedulePoll() {
  if (pollTimer !== undefined) return;
  pollTimer = window.setInterval(() => {
    refresh().catch(() => {});
  }, 800);
}

function stopPoll() {
  if (pollTimer !== undefined) {
    clearInterval(pollTimer);
    pollTimer = undefined;
  }
}

function showDisconnected() {
  stopPoll();
  $("state-disconnected").hidden = false;
  $("state-connected").hidden = true;
  $("state-error").hidden = true;
  $("state-pending").hidden = true;
}

function showConnected(state: PopupState) {
  stopPoll();
  $("state-disconnected").hidden = true;
  $("state-connected").hidden = false;
  $("state-error").hidden = true;
  $("state-pending").hidden = true;
  ($("address-checksum") as HTMLDivElement).textContent = state.address ?? "";

  renderGbaLock(state);
}

/** Renders the active-network badge (GBA is the authority). Two states:
 *  - locked: cached policy exists -> active chain for dApps
 *  - unknown: GBA hasn't answered yet / firmware too old -> "press refresh" */
function renderGbaLock(state: PopupState) {
  const status = $("gba-lock-status") as HTMLDivElement;
  if (!state.gbaPolicyKnown) {
    status.className = "gba-lock-status unknown";
    status.innerHTML = `<span class="lock-dot"></span>
      <span class="lock-name">no lock yet</span>
      <span class="lock-id">press refresh</span>`;
    return;
  }
  status.className = "gba-lock-status match";
  status.innerHTML = `<span class="lock-dot"></span>
    <span class="lock-name">${escapeHtml(state.chainName)}</span>
    <span class="lock-id">id ${state.chainId} &middot; ${escapeHtml(state.nativeSymbol)}</span>`;
}

function showError(msg: string) {
  stopPoll();
  $("state-disconnected").hidden = true;
  $("state-connected").hidden = true;
  $("state-error").hidden = false;
  $("state-pending").hidden = true;
  ($("error-msg") as HTMLParagraphElement).textContent = msg;
}

function showPending(info: ActiveRequestInfo) {
  $("state-disconnected").hidden = true;
  $("state-connected").hidden = true;
  $("state-error").hidden = true;
  $("state-pending").hidden = false;

  const r = info.request;
  const titleEl = $("pending-title") as HTMLHeadingElement;
  const bodyEl = $("pending-body");
  const parts: string[] = [];

  // Origin + signer ALWAYS at the top
  parts.push(originBlock(r.origin));
  parts.push(field("Signer", short(r.address), true, r.address));

  switch (r.kind) {
    case "send_tx":
    case "sign_tx": {
      titleEl.textContent = r.kind === "send_tx"
        ? "Send Transaction"
        : "Sign Transaction (no broadcast)";

      // Prominent ID at the top: the user must verify the GBA shows the
      // same hash prefix.
      parts.push(idBlock(r.signingHashHex ?? "0x"));

      // Network + symbol
      parts.push(field("Network", `${r.chainName ?? "?"} (${r.chainId})`));

      // To + decoded function
      parts.push(field("To", short(r.to ?? "<contract creation>"), true, r.to ?? ""));
      if (r.decodedSummary) {
        parts.push(field("Action", r.decodedSummary));
      } else if ((r.dataLen ?? 0) > 0) {
        parts.push(field(
          "Action",
          `unknown call (selector ${(r.dataHex ?? "0x").slice(0, 10)})`,
        ));
      } else {
        parts.push(field("Action", "Plain transfer (no data)"));
      }

      const sym = r.nativeSymbol ?? "ETH";
      parts.push(field("Value", formatValue(r.valueHex ?? "0x0", sym)));

      parts.push(field("Nonce", String(parseHex(r.nonceHex ?? "0x0"))));
      parts.push(field("Gas limit", String(parseHex(r.gasHex ?? "0x0"))));
      if (r.maxFeeHex) {
        parts.push(field("Max fee per gas", formatGwei(r.maxFeeHex)));
      }
      if (r.tipHex) {
        parts.push(field("Priority tip", formatGwei(r.tipHex)));
      }
      if (r.gasPriceHex) {
        parts.push(field("Gas price", formatGwei(r.gasPriceHex)));
      }
      if ((r.dataLen ?? 0) > 0) {
        parts.push(`<details class="pending-field">
          <summary class="pending-field-label">Calldata (${r.dataLen} bytes)</summary>
          <div class="pending-text mono">${escapeHtml(r.dataHex ?? "")}</div>
        </details>`);
      }
      break;
    }
    case "personal_sign":
      titleEl.textContent = "personal_sign (EIP-191)";
      parts.push(idBlock(r.eip191HashHex ?? "0x"));
      parts.push(`<div class="pending-field">
        <div class="pending-field-label">Message (${r.msgHexLen ?? 0} bytes)</div>
        <div class="pending-text">${escapeHtml(r.msgUtf8 ?? "")}</div>
      </div>`);
      break;
    case "typed_data":
      titleEl.textContent = `signTypedData_v4 (${r.primaryType ?? ""})`;
      parts.push(idBlock(r.digestHex ?? "0x"));
      parts.push(field("Domain", String(r.domainName ?? "")));
      parts.push(field("Chain", String(r.chainId ?? 0)));
      parts.push(`<div class="pending-field">
        <div class="pending-field-label">Pretty-printed message (this is what the GBA shows)</div>
        <div class="pending-text">${escapeHtml(r.humanText ?? "")}</div>
      </div>`);
      parts.push(`<details class="pending-field">
        <summary class="pending-field-label">domainSeparator</summary>
        <div class="pending-field-value mono">${escapeHtml(r.domainSepHex ?? "")}</div>
      </details>`);
      parts.push(`<details class="pending-field">
        <summary class="pending-field-label">messageHash</summary>
        <div class="pending-field-value mono">${escapeHtml(r.msgHashHex ?? "")}</div>
      </details>`);
      break;
    default:
      titleEl.textContent = String(r.kind ?? "?");
  }
  bodyEl.innerHTML = parts.join("");
}

function field(label: string, value: string, mono = false, fullValue?: string): string {
  const cls = mono ? "pending-field-value mono" : "pending-field-value";
  const title = fullValue ? ` title="${escapeHtml(fullValue)}"` : "";
  return `<div class="pending-field">
    <div class="pending-field-label">${escapeHtml(label)}</div>
    <div class="${cls}"${title}>${escapeHtml(value)}</div>
  </div>`;
}

function originBlock(origin: string): string {
  let host = origin;
  try {
    host = new URL(origin).host;
  } catch { /* ignore */ }
  return `<div class="pending-origin">
    <span class="pending-origin-label">Request from</span>
    <span class="pending-origin-host" title="${escapeHtml(origin)}">${escapeHtml(host)}</span>
  </div>`;
}

function idBlock(hashHex: string): string {
  // ID = first 4 bytes of the signing hash (8 hex chars). Matches what
  // the GBA shows on its confirmation screen. The user must see THE
  // SAME ID in both places.
  const trimmed = hashHex.startsWith("0x") ? hashHex.slice(2) : hashHex;
  const short8 = trimmed.slice(0, 8);
  return `<div class="pending-id" title="Compare this ID with the one the GBA shows. If they differ, DO NOT sign.">
    <span class="pending-id-label">TX ID</span>
    <span class="pending-id-value">0x${escapeHtml(short8)}</span>
    <details class="pending-id-full">
      <summary class="muted small">show full hash</summary>
      <div class="pending-field-value mono">${escapeHtml(hashHex)}</div>
    </details>
  </div>`;
}

function short(v: string): string {
  if (!v || v.length < 14) return v;
  if (v.startsWith("0x") && v.length === 42) {
    return `${v.slice(0, 10)}...${v.slice(-8)}`;
  }
  if (v.length > 24) return `${v.slice(0, 12)}...${v.slice(-8)}`;
  return v;
}

function escapeHtml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function parseHex(h: string): bigint {
  try { return BigInt(h || "0x0"); } catch { return 0n; }
}

function formatValue(weiHex: string, symbol: string): string {
  try {
    const wei = BigInt(weiHex || "0x0");
    if (wei === 0n) return `0 ${symbol}`;
    const whole = wei / 10n ** 18n;
    const frac = wei % 10n ** 18n;
    if (whole === 0n) {
      // < 1 token: show as decimal with up to 6 digits
      const fracStr = frac.toString().padStart(18, "0").slice(0, 6).replace(/0+$/, "");
      return fracStr ? `0.${fracStr} ${symbol}` : `${wei.toString()} wei`;
    }
    const fracTrim = frac
      .toString()
      .padStart(18, "0")
      .slice(0, 6)
      .replace(/0+$/, "");
    return fracTrim ? `${whole}.${fracTrim} ${symbol}` : `${whole} ${symbol}`;
  } catch {
    return `${weiHex} (raw)`;
  }
}

function formatGwei(weiHex: string): string {
  try {
    const wei = BigInt(weiHex || "0x0");
    const gwei = Number(wei) / 1e9;
    return `${gwei.toFixed(2)} gwei`;
  } catch {
    return weiHex;
  }
}

$("btn-connect").addEventListener("click", async () => {
  // Opening the WebSerial dialog directly from the popup fails on many
  // setups because the popup loses focus (and therefore closes) as soon
  // as Chrome shows the port picker, which produces an instant
  // "No port selected". The robust fix is to delegate the port-pick flow
  // to a regular tab, which stays alive while the dialog is open.
  await chrome.tabs.create({
    url: chrome.runtime.getURL("src/connect/connect.html"),
  });
  // Close the popup; the tab takes it from here and we'll refresh on
  // the next popup open.
  window.close();
});

$("btn-disconnect").addEventListener("click", async () => {
  await chrome.runtime.sendMessage({ kind: "popup-disconnect" });
  await refresh();
});

$("btn-retry").addEventListener("click", () => refresh());

$("btn-cancel-active").addEventListener("click", async () => {
  await chrome.runtime.sendMessage({ kind: "popup-cancel-active" });
  await refresh();
});

$("btn-settings").addEventListener("click", () => {
  chrome.runtime.openOptionsPage();
});

$("btn-refresh-lock").addEventListener("click", async () => {
  // Re-read the chain-lock policy from the GBA (open port -> get_policy ->
  // close). Takes ~1s. Used when the user changes the lock with L/R on
  // the cartridge while the popup is open.
  const status = $("gba-lock-status") as HTMLDivElement;
  status.className = "gba-lock-status unknown";
  status.innerHTML = `<span class="lock-dot"></span>
    <span class="lock-name">querying GBA...</span>`;
  try {
    await chrome.runtime.sendMessage({ kind: "popup-refresh-gba-policy" });
  } catch {
    /* the 'gbaPolicyChanged' broadcast refreshes the badge anyway */
  }
  await refresh();
});

// Listen for live policy changes (when another part of the extension
// updates it, e.g. after REJECT_CHAIN). This way the badge needs no poll.
chrome.runtime.onMessage.addListener((msg) => {
  if (msg?.kind === "gba-event" && msg.ev?.type === "gbaPolicyChanged") {
    refresh().catch(() => {});
  }
});

refresh().catch((e) => showError(e instanceof Error ? e.message : String(e)));
