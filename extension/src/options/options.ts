// Settings page: per-chain RPC overrides.
//
// The user can prepend their own URLs to each network's default list.
// Failover in rpcCall iterates in order, so the user's URLs are tried
// first; if they all fail the public ones kick in (free resilience).
//
// Persistence lives in chrome.storage.local (managed by session.ts).
// This page reads it directly via chrome.storage (not via the SW) to
// avoid unnecessary roundtrips.

import { DEFAULT_NETWORKS } from "../lib/networks";
import type { NetworkInfo } from "../lib/types";

const STORAGE_KEY = "coldpakku-state";

interface PersistedState {
  rpcOverrides?: Record<string, string[]>;
  // Other fields exist but we don't touch them here.
}

// Mutable local state: chainId -> edited custom URLs (not persisted
// until the user clicks "save" on that network).
const editing: Record<string, string[]> = {};
let dirty = new Set<string>();

async function loadOverrides(): Promise<Record<string, string[]>> {
  const r = await chrome.storage.local.get(STORAGE_KEY);
  const s = (r[STORAGE_KEY] ?? {}) as PersistedState;
  return s.rpcOverrides ?? {};
}

async function saveOverridesForChain(chainId: number, urls: string[]): Promise<void> {
  const r = await chrome.storage.local.get(STORAGE_KEY);
  const s = (r[STORAGE_KEY] ?? {}) as PersistedState;
  const key = String(chainId);
  const next: Record<string, string[]> = { ...(s.rpcOverrides ?? {}) };
  if (urls.length === 0) {
    delete next[key];
  } else {
    next[key] = urls;
  }
  await chrome.storage.local.set({
    [STORAGE_KEY]: { ...s, rpcOverrides: next },
  });
}

// ---------------------------------------------------------------------------
// Render
// ---------------------------------------------------------------------------

function renderAll(overrides: Record<string, string[]>): void {
  const root = document.getElementById("networks-root")!;
  root.innerHTML = "";

  // Initialise the editable state from persisted overrides.
  for (const n of DEFAULT_NETWORKS) {
    const key = String(n.chainId);
    editing[key] = [...(overrides[key] ?? [])];
  }
  dirty = new Set();

  for (const n of DEFAULT_NETWORKS) {
    root.appendChild(renderCard(n));
  }
  updateStatus("");
}

function renderCard(n: NetworkInfo): HTMLElement {
  const card = document.createElement("section");
  const key = String(n.chainId);
  const isTestnet = /\(test\)/i.test(n.name);
  card.className = "network-card" + (isTestnet ? " testnet" : "");
  card.dataset.chainId = key;

  const head = document.createElement("div");
  head.className = "network-head";
  head.innerHTML = `
    <span class="network-name"></span>
    <span class="network-id"></span>
    ${isTestnet ? `<span class="network-tag test">testnet</span>` : ""}
  `;
  (head.querySelector(".network-name") as HTMLElement).textContent = n.name;
  (head.querySelector(".network-id") as HTMLElement).textContent =
    `chainId ${n.chainId}`;
  card.appendChild(head);

  const list = document.createElement("div");
  list.className = "url-list";
  list.id = `urls-${key}`;
  card.appendChild(list);

  const actions = document.createElement("div");
  actions.className = "network-actions";
  actions.innerHTML = `
    <button class="add">+ Add custom URL</button>
    <button class="test">Test</button>
    <button class="reset danger" title="Remove YOUR URLs for this network; revert to defaults">Reset</button>
    <button class="save primary" disabled>Save</button>
    <span class="test-result"></span>
  `;
  card.appendChild(actions);

  // Wire-up
  (actions.querySelector(".add") as HTMLButtonElement).onclick = () => {
    editing[key].push("");
    markDirty(key);
    rerenderUrls(n);
  };
  (actions.querySelector(".test") as HTMLButtonElement).onclick = () =>
    testNetwork(n, card);
  (actions.querySelector(".reset") as HTMLButtonElement).onclick = async () => {
    if (!confirm(`Remove your custom URLs for ${n.name}?`)) return;
    editing[key] = [];
    await saveOverridesForChain(n.chainId, []);
    dirty.delete(key);
    rerenderUrls(n);
    updateSaveButton(card, key);
    updateStatus(`Reset ${n.name}.`);
  };
  (actions.querySelector(".save") as HTMLButtonElement).onclick = async () => {
    const clean = editing[key].map((u) => u.trim()).filter((u) => u.length > 0);
    // Light validation: must be an http(s) URL
    for (const u of clean) {
      if (!/^https?:\/\/.+/i.test(u)) {
        updateStatus(`Invalid URL: "${u}". Must start with http:// or https://`);
        return;
      }
    }
    editing[key] = clean;
    await saveOverridesForChain(n.chainId, clean);
    dirty.delete(key);
    rerenderUrls(n);
    updateSaveButton(card, key);
    updateStatus(`Saved ${n.name}.`);
  };

  rerenderUrls(n);
  return card;
}

function rerenderUrls(n: NetworkInfo): void {
  const key = String(n.chainId);
  const list = document.getElementById(`urls-${key}`);
  if (!list) return;
  list.innerHTML = "";

  // 1) The user's URLs (editable)
  editing[key].forEach((url, idx) => {
    const row = document.createElement("div");
    row.className = "url-row custom";
    const input = document.createElement("input");
    input.type = "text";
    input.value = url;
    input.placeholder = "https://your-rpc.example.com";
    input.oninput = () => {
      editing[key][idx] = input.value;
      markDirty(key);
    };
    const rm = document.createElement("button");
    rm.className = "icon danger";
    rm.title = "Remove this URL";
    rm.textContent = "×";
    rm.onclick = () => {
      editing[key].splice(idx, 1);
      markDirty(key);
      rerenderUrls(n);
    };
    row.appendChild(input);
    row.appendChild(rm);
    list.appendChild(row);
  });

  // 2) Defaults (read-only, shown at the end so the user can see them)
  n.rpcUrls.forEach((url) => {
    const row = document.createElement("div");
    row.className = "url-row default";
    const input = document.createElement("input");
    input.type = "text";
    input.value = url;
    input.disabled = true;
    row.appendChild(input);
    list.appendChild(row);
  });

  const card = document.querySelector<HTMLElement>(`.network-card[data-chain-id="${key}"]`);
  if (card) updateSaveButton(card, key);
}

function updateSaveButton(card: HTMLElement, key: string): void {
  const btn = card.querySelector<HTMLButtonElement>(".save");
  if (btn) btn.disabled = !dirty.has(key);
  if (dirty.has(key)) card.classList.add("changed");
  else card.classList.remove("changed");
}

function markDirty(key: string): void {
  dirty.add(key);
  const card = document.querySelector<HTMLElement>(`.network-card[data-chain-id="${key}"]`);
  if (card) updateSaveButton(card, key);
}

function updateStatus(s: string): void {
  const el = document.getElementById("status");
  if (el) el.textContent = s;
}

// ---------------------------------------------------------------------------
// Test: fires eth_blockNumber against the first custom URL (or the first
// default if there is no custom) and reports latency / error.
// ---------------------------------------------------------------------------

async function testNetwork(n: NetworkInfo, card: HTMLElement): Promise<void> {
  const key = String(n.chainId);
  const result = card.querySelector(".test-result") as HTMLElement;
  result.className = "test-result";
  result.textContent = "testing...";

  const effective = [...editing[key], ...n.rpcUrls];
  if (effective.length === 0) {
    result.className = "test-result err";
    result.textContent = "no URLs";
    return;
  }

  const url = effective[0];
  const t0 = performance.now();
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_blockNumber", params: [] }),
    });
    const j = await res.json();
    const dt = Math.round(performance.now() - t0);
    if (j.error) {
      result.className = "test-result err";
      result.textContent = `err: ${j.error.message ?? "rpc error"}`;
    } else if (j.result) {
      const blockNo = parseInt(j.result, 16);
      result.className = "test-result ok";
      result.textContent = `ok — block ${blockNo} (${dt}ms)`;
    } else {
      result.className = "test-result err";
      result.textContent = "no result";
    }
  } catch (e) {
    result.className = "test-result err";
    result.textContent = `failed: ${e instanceof Error ? e.message : String(e)}`;
  }
}

// ---------------------------------------------------------------------------
// Import / export
// ---------------------------------------------------------------------------

function exportConfig(): void {
  const blob = new Blob([JSON.stringify(editing, null, 2)], {
    type: "application/json",
  });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "coldpakku-rpcs.json";
  a.click();
  URL.revokeObjectURL(a.href);
}

async function importConfig(file: File): Promise<void> {
  try {
    const txt = await file.text();
    const parsed = JSON.parse(txt) as Record<string, unknown>;
    if (!parsed || typeof parsed !== "object") {
      updateStatus("Import: invalid JSON");
      return;
    }
    // Persist every valid override in a single pass
    for (const [k, v] of Object.entries(parsed)) {
      if (!Array.isArray(v)) continue;
      const urls = (v as unknown[])
        .filter((u): u is string => typeof u === "string")
        .map((u) => u.trim())
        .filter((u) => /^https?:\/\/.+/i.test(u));
      const chainId = parseInt(k, 10);
      if (!Number.isFinite(chainId) || chainId <= 0) continue;
      await saveOverridesForChain(chainId, urls);
    }
    const overrides = await loadOverrides();
    renderAll(overrides);
    updateStatus("Import OK.");
  } catch (e) {
    updateStatus(`Import error: ${e instanceof Error ? e.message : String(e)}`);
  }
}

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------

loadOverrides().then((ov) => renderAll(ov));

document.getElementById("btn-export")!.addEventListener("click", exportConfig);
document.getElementById("btn-import")!.addEventListener("click", () => {
  (document.getElementById("file-import") as HTMLInputElement).click();
});
document.getElementById("file-import")!.addEventListener("change", (ev) => {
  const f = (ev.target as HTMLInputElement).files?.[0];
  if (f) importConfig(f);
});
