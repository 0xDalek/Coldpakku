// Persistent state for the extension. Lives in chrome.storage.local so
// it survives service-worker restarts (MV3 puts it to sleep after 30s).
//
// What we store:
//   - address: 20B raw + checksum string
//   - active chainId (default 1 = mainnet)
//   - custom networks added via wallet_addEthereumChain
//   - per-origin permissions: which dApps can see eth_accounts

import type { Address, NetworkInfo } from "../lib/types";
import { DEFAULT_NETWORKS } from "../lib/networks";

interface PersistedState {
  addressBytesB64: string | null;
  addressChecksum: Address | null;
  customNetworks: NetworkInfo[];
  authorizedOrigins: string[];
  // Custom RPC URLs PER CHAIN ID. If an entry exists for a chainId, it
  // is PREPENDED to the default list (failover follows list order).
  // Keyed by chainId as a string (chrome.storage serializes to JSON and
  // doesn't distinguish number vs string keys cleanly).
  rpcOverrides: Record<string, string[]>;
  // Network locked on the GBA (chain_id; 0 = unknown or no lock). THE
  // GBA IS THE AUTHORITY: this value is the sole definition of the
  // active network seen by dApps. Refreshed on connect, on every tx,
  // on each periodic refresh, and on demand from the popup. The only
  // real source of truth lives in the cartridge's SRAM; this is just a
  // cache.
  gbaPolicyChainId: number;
  // Timestamp (ms epoch) of the last cache update. Lets the dispatcher
  // decide whether a cached response is fresh enough or whether to
  // re-query the GBA synchronously before serving eth_chainId.
  gbaPolicyTs: number;
}

const DEFAULT_STATE: PersistedState = {
  addressBytesB64: null,
  addressChecksum: null,
  customNetworks: [],
  authorizedOrigins: [],
  rpcOverrides: {},
  gbaPolicyChainId: 0,
  gbaPolicyTs: 0,
};

const KEY = "coldpakku-state";

export async function loadState(): Promise<PersistedState> {
  const r = await chrome.storage.local.get(KEY);
  const stored = r[KEY];
  if (!stored) return { ...DEFAULT_STATE };
  return { ...DEFAULT_STATE, ...stored };
}

export async function saveState(s: PersistedState): Promise<void> {
  await chrome.storage.local.set({ [KEY]: s });
}

export async function setAddress(addrBytes: Uint8Array, checksum: Address): Promise<void> {
  const s = await loadState();
  s.addressBytesB64 = bytesToB64(addrBytes);
  s.addressChecksum = checksum;
  await saveState(s);
  notifyAccountsChanged([checksum]);
}

export async function clearAddress(): Promise<void> {
  const s = await loadState();
  s.addressBytesB64 = null;
  s.addressChecksum = null;
  s.authorizedOrigins = [];
  await saveState(s);
  notifyAccountsChanged([]);
}

export async function getAddressBytes(): Promise<Uint8Array | null> {
  const s = await loadState();
  if (!s.addressBytesB64) return null;
  return b64ToBytes(s.addressBytesB64);
}

/** Returns the active network according to the GBA (the authority). If
 *  the GBA is not connected yet (no cached policy), falls back to
 *  Ethereum mainnet so `eth_chainId` always has a reasonable answer and
 *  dApps don't break at boot.
 *
 *  IMPORTANT: this value changes automatically when the user navigates
 *  with L/R on the cartridge. The extension does not have "its own"
 *  active network separate from the GBA — there is ONE source of truth,
 *  and it lives in the cartridge's SRAM. */
export async function getActiveNetwork(): Promise<NetworkInfo> {
  const s = await loadState();
  const all = [...DEFAULT_NETWORKS, ...s.customNetworks];
  const id = s.gbaPolicyChainId || 1;  /* fallback Eth mainnet */
  const base = all.find((n) => n.chainId === id) ?? DEFAULT_NETWORKS[0];
  return applyRpcOverrides(base, s.rpcOverrides);
}

/** Prepends the user's RPC URLs (if any for this chainId) to the
 *  defaults. The failover logic in rpc-passthrough iterates the list in
 *  order, so the user's URLs are tried first; if they all fail we fall
 *  back to the public ones. This buys resilience for free. */
function applyRpcOverrides(
  net: NetworkInfo,
  overrides: Record<string, string[]>,
): NetworkInfo {
  const custom = overrides[String(net.chainId)];
  if (!custom || custom.length === 0) return net;
  return { ...net, rpcUrls: [...custom, ...net.rpcUrls] };
}

/** Age of the policy cache in ms. Useful to decide whether a cached
 *  eth_chainId/net_version response is good enough or whether to
 *  re-query the GBA before answering. */
export async function getGbaPolicyAgeMs(): Promise<number> {
  const s = await loadState();
  if (!s.gbaPolicyTs) return Number.MAX_SAFE_INTEGER;
  return Date.now() - s.gbaPolicyTs;
}

export async function getAllNetworks(): Promise<NetworkInfo[]> {
  const s = await loadState();
  const all = [...DEFAULT_NETWORKS, ...s.customNetworks];
  return all.map((n) => applyRpcOverrides(n, s.rpcOverrides));
}

export async function getRpcOverrides(): Promise<Record<string, string[]>> {
  const s = await loadState();
  return { ...s.rpcOverrides };
}

/** Replaces the whole override list for `chainId`. An empty list clears
 *  the override (equivalent to "use defaults"). */
export async function setRpcOverridesForChain(
  chainId: number,
  urls: string[],
): Promise<void> {
  const s = await loadState();
  const key = String(chainId);
  if (urls.length === 0) {
    delete s.rpcOverrides[key];
  } else {
    s.rpcOverrides[key] = urls;
  }
  await saveState(s);
}

export async function addCustomNetwork(net: NetworkInfo): Promise<void> {
  const s = await loadState();
  if (s.customNetworks.find((n) => n.chainId === net.chainId)) return;
  if (DEFAULT_NETWORKS.find((n) => n.chainId === net.chainId)) return;
  s.customNetworks.push(net);
  await saveState(s);
}

export async function authorizeOrigin(origin: string): Promise<void> {
  const s = await loadState();
  if (!s.authorizedOrigins.includes(origin)) {
    s.authorizedOrigins.push(origin);
    await saveState(s);
  }
}

export async function isAuthorized(origin: string): Promise<boolean> {
  const s = await loadState();
  return s.authorizedOrigins.includes(origin);
}

/** Revokes an origin's access to the wallet. Notifies any open dApp at
 *  that origin with accountsChanged([]) so they see the logout. */
export async function revokeOrigin(origin: string): Promise<void> {
  const s = await loadState();
  if (!s.authorizedOrigins.includes(origin)) return;
  s.authorizedOrigins = s.authorizedOrigins.filter((o) => o !== origin);
  await saveState(s);
  notifyAccountsChanged([]);
}

/** Caches the chain lock reported by the GBA via PROTO_GET_POLICY. The
 *  GBA is the network authority, so if the new chainId differs from the
 *  cached one we ALSO emit an EIP-1193 `chainChanged` event so dApps
 *  refresh on their own without the user reloading.
 *
 *  Called from:
 *    - connectAndCacheAddress (on connect)
 *    - dispatcher after receiving REJECT_CHAIN (GBA just revealed its lock)
 *    - popup-refresh-gba-policy (manual popup button)
 *    - popup-state if cache > 10s (opportunistic refresh on popup open)
 *    - any path that opens a serial session (opportunistic auto-sync) */
export async function setGbaPolicyChainId(chainId: number): Promise<void> {
  const s = await loadState();
  const changed = s.gbaPolicyChainId !== chainId;
  s.gbaPolicyChainId = chainId;
  s.gbaPolicyTs = Date.now();
  await saveState(s);
  if (changed) {
    // 1) Live popup badge update
    broadcastEvent({ type: "gbaPolicyChanged", data: chainId });
    // 2) EIP-1193 chainChanged: loaded dApps refresh themselves. The
    //    GBA changing network is the equivalent of MetaMask's "switch
    //    network" from the dApp's perspective.
    if (chainId > 0) {
      const chainIdHex = `0x${chainId.toString(16)}`;
      notifyChainChanged(chainIdHex);
    }
  }
}

export async function getGbaPolicyChainId(): Promise<number> {
  const s = await loadState();
  return s.gbaPolicyChainId | 0;
}

// ============================================================================
// Events: the extension propagates accountsChanged / chainChanged to
// every tab with an authorized dApp.
// ============================================================================

function notifyAccountsChanged(accounts: Address[]) {
  broadcastEvent({ type: "accountsChanged", data: accounts });
}

function notifyChainChanged(chainIdHex: string) {
  broadcastEvent({ type: "chainChanged", data: chainIdHex });
}

function broadcastEvent(ev: { type: string; data: unknown }) {
  // 1) Tabs with a content-script (where each dApp's injected provider lives)
  chrome.tabs.query({}, (tabs) => {
    for (const tab of tabs) {
      if (tab.id === undefined) continue;
      chrome.tabs.sendMessage(tab.id, { kind: "gba-event", ev }).catch(() => {
        /* tab without content script or closed: ignore */
      });
    }
  });
  // 2) Extension pages (popup, connect.html, confirm.html). This does
  //    not reach content-scripts but does reach the popup, which is
  //    exactly what the "GBA chain lock" badge needs to auto-refresh.
  chrome.runtime.sendMessage({ kind: "gba-event", ev }).catch(() => {
    /* no listeners (popup closed): ignore */
  });
}

// ============================================================================
// Base64 helpers (chrome.storage doesn't accept Uint8Array directly)
// ============================================================================

function bytesToB64(b: Uint8Array): string {
  let s = "";
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s);
}

function b64ToBytes(b64: string): Uint8Array {
  const s = atob(b64);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}
