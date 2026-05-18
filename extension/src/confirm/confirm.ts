// Render the confirm popup. Asks the SW for the "pending request" and
// draws the matching detail. From here the user can only CANCEL (the
// approval happens by pressing A on the GBA — this is intentional, so
// the user cannot confirm without having seen the data on the hardware).

export {};

interface ConfirmRequest {
  kind: "send_tx" | "sign_tx" | "personal_sign" | "typed_data";
  origin: string;
  address: string;
  // send_tx / sign_tx
  chainId?: number;
  to?: string | null;
  valueHex?: string;
  dataLen?: number;
  // personal_sign
  msgUtf8?: string;
  msgHexLen?: number;
  // typed_data
  primaryType?: string;
  domainName?: string;
  humanText?: string;
  domainSepHex?: string;
  msgHashHex?: string;
}

const $ = (id: string) => document.getElementById(id) as HTMLElement;

function field(label: string, value: string, mono = false): string {
  const cls = mono ? "field-value mono" : "field-value";
  return `<div class="field">
    <div class="field-label">${label}</div>
    <div class="${cls}">${escape(value)}</div>
  </div>`;
}

function escape(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function formatValue(weiHex: string): string {
  const wei = BigInt(weiHex || "0x0");
  const eth = Number(wei) / 1e18;
  if (eth === 0) return "0 ETH";
  if (eth < 0.0001) return `${wei.toString()} wei`;
  return `${eth.toFixed(6)} ETH`;
}

async function load() {
  const r = await chrome.runtime.sendMessage({ kind: "confirm-fetch" });
  const req: ConfirmRequest | null = r?.request ?? null;
  if (!req) {
    $("title").textContent = "No request";
    $("main").innerHTML = `<p class="muted">No pending requests.</p>`;
    return;
  }
  render(req);
}

function render(req: ConfirmRequest) {
  const sec: string[] = [];
  sec.push(`<div class="origin">
    <span class="label">From dApp:</span> ${escape(req.origin)}
  </div>`);
  sec.push(field("Signer account", req.address, true));

  switch (req.kind) {
    case "send_tx":
    case "sign_tx":
      $("title").textContent = req.kind === "send_tx"
        ? "Send Transaction"
        : "Sign Transaction (no broadcast)";
      sec.push(field("Chain ID", String(req.chainId)));
      sec.push(field("To", req.to ?? "<contract creation>", true));
      sec.push(field("Value", formatValue(req.valueHex ?? "0x0")));
      sec.push(field("Data", `${req.dataLen ?? 0} bytes`));
      break;
    case "personal_sign": {
      $("title").textContent = "personal_sign (EIP-191)";
      sec.push(`<div class="field">
        <div class="field-label">Message (${req.msgHexLen ?? 0} bytes)</div>
        <pre class="text">${escape(req.msgUtf8 ?? "")}</pre>
      </div>`);
      break;
    }
    case "typed_data":
      $("title").textContent = `signTypedData_v4 (${escape(req.primaryType ?? "")})`;
      sec.push(field("Domain", req.domainName ?? ""));
      sec.push(field("ChainId", String(req.chainId ?? 0)));
      sec.push(`<div class="field">
        <div class="field-label">Pretty-printed message (this is what the GBA shows)</div>
        <pre class="text">${escape(req.humanText ?? "")}</pre>
      </div>`);
      sec.push(`<div class="field">
        <div class="field-label">EIP-712 hashes (the GBA displays these for verification)</div>
        <div class="hashes">
          <div><b>domainSeparator</b>${escape(req.domainSepHex ?? "")}</div>
          <div><b>messageHash</b>${escape(req.msgHashHex ?? "")}</div>
        </div>
      </div>`);
      break;
  }
  $("main").innerHTML = sec.join("");
}

$("btn-cancel").addEventListener("click", async () => {
  await chrome.runtime.sendMessage({
    kind: "confirm-decision",
    payload: { approved: false, error: "user cancelled in popup" },
  });
  window.close();
});

load().catch((e) => {
  $("main").innerHTML = `<p class="muted">${escape(String(e))}</p>`;
});
