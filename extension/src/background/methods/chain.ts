// Handlers for network-related methods:
//   eth_chainId, net_version, wallet_switchEthereumChain, wallet_addEthereumChain
//
// All "source of truth" for the active network lives in the GBA. These
// handlers only report the current lock to the dApp, or — if the dApp
// asks for a different network — tell it "switch it on the cartridge"
// via the standard 4902 error.

import type { Hex, NetworkInfo } from "../../lib/types";
import { RpcError } from "../rpc-passthrough";
import { withGbaSession } from "../serial-bridge";
import {
  addCustomNetwork,
  getActiveNetwork,
  getAllNetworks,
  getGbaPolicyAgeMs,
  setGbaPolicyChainId,
} from "../session";
import { findNetworkByChainId } from "../../lib/networks";
import { parseChainId } from "./_shared";

/** wallet_switchEthereumChain: the dApp asks to switch to a specific network.
 *  In GBA-Signer the GBA is the only authority: we CANNOT change the
 *  network from here. Two cases:
 *
 *   a) The dApp asks for the network the GBA is ALREADY locked to -> no-op.
 *   b) The dApp asks for a different one -> error 4902 with instructions
 *      to switch the lock with L/R on the cartridge. */
export async function walletSwitchChain(p: { chainId: Hex | number }): Promise<null> {
  const requested = parseChainId(p.chainId);
  await maybeRefreshPolicyInBg().catch(() => {});
  const active = await getActiveNetwork();
  if (active.chainId === requested) return null;
  const reqNet = findNetworkByChainId(requested, await getAllNetworks());
  const reqName = reqNet?.name ?? `chainId ${requested}`;
  throw new RpcError(
    4902,
    `Network controlled by the GBA cartridge. ` +
      `It is currently locked to ${active.name} (chainId ${active.chainId}); ` +
      `you asked for ${reqName}. ` +
      `Press L or R on the GBA's "awaiting transaction" screen to switch ` +
      `to ${reqName}. The dApp will then auto-update.`,
    { current: active.chainId, requested },
  );
}

export async function walletAddChain(p: any): Promise<null> {
  // EIP-3085: chainId is usually a hex string, some dApps send a number.
  // We just store it in customNetworks to resolve name/RPC when the GBA
  // ends up on that chainId; we do NOT auto-switch.
  if (!p?.chainId || !Array.isArray(p?.rpcUrls) || p.rpcUrls.length === 0) {
    throw new RpcError(-32602, "wallet_addEthereumChain requires chainId and rpcUrls");
  }
  const id = parseChainId(p.chainId);
  const hex = ("0x" + id.toString(16)) as Hex;
  const existing = findNetworkByChainId(id, await getAllNetworks());
  if (!existing) {
    const net: NetworkInfo = {
      chainId: id,
      chainIdHex: hex,
      name: String(p.chainName ?? `Chain ${id}`),
      rpcUrls: p.rpcUrls,
      nativeCurrency: p.nativeCurrency ?? {
        name: "Ether",
        symbol: "ETH",
        decimals: 18,
      },
      blockExplorerUrls: p.blockExplorerUrls,
    };
    await addCustomNetwork(net);
  }
  const active = await getActiveNetwork();
  if (active.chainId === id) return null;
  throw new RpcError(
    4902,
    `Network ${p.chainName ?? id} added to the cache, but the GBA cartridge ` +
      `is locked to ${active.name} (chainId ${active.chainId}). ` +
      `Press L or R on the GBA to switch to chainId ${id}.`,
    { current: active.chainId, requested: id },
  );
}

/** Opportunistic policy refresh. Non-blocking: if the cache is fresh
 *  (<15s) or a session is already in flight (mutex), it does nothing.
 *  If it does run, it emits chainChanged automatically when the network
 *  changes. */
let bgRefreshInFlight = false;
export async function maybeRefreshPolicyInBg(): Promise<void> {
  if (bgRefreshInFlight) return;
  const ageMs = await getGbaPolicyAgeMs();
  if (ageMs < 15_000) return;
  bgRefreshInFlight = true;
  try {
    await refreshGbaPolicy();
  } catch {
    /* no GBA connected, fail silently */
  } finally {
    bgRefreshInFlight = false;
  }
}

/** Re-queries the policy from the GBA. Used by the popup when the user
 *  presses "refresh chain lock". */
export async function refreshGbaPolicy(): Promise<number> {
  const chainId = await withGbaSession((session) => session.getPolicy());
  await setGbaPolicyChainId(chainId).catch(() => {});
  return chainId;
}
