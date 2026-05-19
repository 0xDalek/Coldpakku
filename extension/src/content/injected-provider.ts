// EIP-1193 provider injected into every page (MAIN world). It announces
// itself ONLY via EIP-6963 (does not clobber window.ethereum). Modern
// dApps detect multi-injected EIP-6963 providers; older dApps that only
// read window.ethereum will NOT work with Coldpakku — this is
// deliberate so we don't impersonate other wallets (MetaMask, Rabby...).

export {};

const NS_REQ = "gba-signer:request";
const NS_RES = "gba-signer:response";
const NS_EVT = "gba-signer:event";

// Stable UUID for this provider (used in the EIP-6963 announce).
const PROVIDER_UUID = "9b1e9a5d-3e49-4e1a-a8c6-44edc7c0d5b1";

interface JsonRpcRequest {
  method: string;
  params?: unknown;
}

type Listener = (...args: unknown[]) => void;

class GbaProvider extends EventTarget {
  isGbaSigner = true;
  private nextId = 1;
  private pending = new Map<number, (r: any) => void>();
  private listeners: Record<string, Set<Listener>> = {};

  constructor() {
    super();
    window.addEventListener("message", (ev: MessageEvent) => this.onWindowMessage(ev));
  }

  // EIP-1193 request
  request(req: JsonRpcRequest): Promise<unknown> {
    return new Promise((resolve, reject) => {
      const id = this.nextId++;
      this.pending.set(id, (resp) => {
        if (resp?.error) {
          const err: any = new Error(resp.error.message ?? "RPC error");
          err.code = resp.error.code ?? -32603;
          err.data = resp.error.data;
          reject(err);
        } else {
          resolve(resp?.result);
        }
      });
      window.postMessage(
        { namespace: NS_REQ, id, request: req },
        window.location.origin,
      );
    });
  }

  // EIP-1193 events: aliases over the EventTarget API for MetaMask compat
  on(evt: string, fn: Listener) {
    (this.listeners[evt] ??= new Set()).add(fn);
  }
  removeListener(evt: string, fn: Listener) {
    this.listeners[evt]?.delete(fn);
  }
  emit(evt: string, ...args: unknown[]) {
    this.listeners[evt]?.forEach((l) => {
      try { l(...args); } catch { /* swallow */ }
    });
  }

  // Some connectors (wagmi, RainbowKit, web3-react) call these MetaMask
  // helpers before issuing any request.
  isConnected(): boolean {
    return true;
  }
  // Legacy helper still used by some dApps.
  enable(): Promise<unknown> {
    return this.request({ method: "eth_requestAccounts" });
  }

  private onWindowMessage(ev: MessageEvent) {
    if (ev.source !== window) return;
    const data = ev.data;
    if (!data) return;
    if (data.namespace === NS_RES) {
      const cb = this.pending.get(data.id);
      if (cb) {
        this.pending.delete(data.id);
        cb(data.response);
      }
    } else if (data.namespace === NS_EVT) {
      const ev = data.ev;
      if (ev?.type) this.emit(ev.type, ev.data);
    }
  }
}

const provider = new GbaProvider();

// EIP-6963 announce. dApps using the multi-injected pattern will pick up
// this provider and show it in their selector. The dApp can also
// re-request it at any time via eip6963:requestProvider.
const PROVIDER_INFO = {
  uuid: PROVIDER_UUID,
  name: "Coldpakku",
  icon: "data:image/svg+xml;base64," + btoa(svgIcon()),
  rdns: "tools.gba-signer",
};

function announce() {
  const ev = new CustomEvent("eip6963:announceProvider", {
    detail: Object.freeze({
      info: PROVIDER_INFO,
      provider,
    }),
  });
  window.dispatchEvent(ev);
}

window.addEventListener("eip6963:requestProvider", () => announce());
announce();

// Shortcut: also expose window.gbaSigner unconditionally.
(window as any).gbaSigner = provider;

function svgIcon(): string {
  // Minimal SVG: a stylised GBA cartridge in grey/purple. No fonts or
  // external resources so the data URL is fully self-contained.
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
    <rect x="6" y="14" width="52" height="36" rx="3" fill="#6c4ab6"/>
    <rect x="14" y="22" width="36" height="18" fill="#1a1a2e"/>
    <rect x="14" y="22" width="36" height="2" fill="#6cf"/>
    <text x="32" y="36" text-anchor="middle" font-family="monospace" font-size="9" fill="#6cf">GBA</text>
  </svg>`;
}
