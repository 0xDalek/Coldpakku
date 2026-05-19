// Dispatcher for RPC requests coming from the injected provider via the
// content-script. It only routes to the implementation in methods/* or
// forwards to the public RPC. Keep it short and flat: any new logic
// goes in methods/.

import type { Address, Hex, RpcRequest } from "../lib/types";
import { rpcCall, RpcError } from "./rpc-passthrough";
import { getActiveNetwork } from "./session";

import {
  connectAndCacheAddress,
  ethAccounts,
  ethRequestAccounts,
  walletGetPermissions,
  walletRequestPermissions,
  walletRevokePermissions,
} from "./methods/accounts";
import {
  maybeRefreshPolicyInBg,
  refreshGbaPolicy,
  walletAddChain,
  walletSwitchChain,
} from "./methods/chain";
import { personalSign, ethSignTypedData } from "./methods/sign";
import { ethSendTransaction, ethSignTransaction } from "./methods/tx";

/** Dispatcher result: result/error following the JSON-RPC shape. */
export interface DispatchResult {
  result?: unknown;
  error?: { code: number; message: string; data?: unknown };
}

/** Called by the content-script for each dApp request.
 *  `origin` is the URL of the frame that issued the call (for auth). */
export async function handleRpc(
  origin: string,
  req: RpcRequest,
): Promise<DispatchResult> {
  // Only log "interesting" methods (signing + session) — skip the
  // eth_call / eth_getBalance / etc. that the dApp polls in a loop.
  const isInteresting = /^(eth_requestAccounts|personal_sign|eth_sign|eth_signTypedData|eth_sendTransaction|eth_signTransaction|wallet_)/.test(
    req.method,
  );
  if (isInteresting) {
    console.log("[gba-rpc] ->", req.method, "from", origin, "params:", req.params);
  }
  try {
    const result = await dispatch(origin, req);
    if (isInteresting) {
      console.log("[gba-rpc] <-", req.method, "OK");
    }
    return { result };
  } catch (e) {
    // -32601 ("method not found") is the correct reply to methods the
    // dApp asks for but we don't support (wallet_getCapabilities,
    // wallet_sendCalls, etc. from EIP-5792). The dApp falls back to the
    // legacy flow and everything works; logging as info instead of
    // error avoids spurious red noise.
    if (e instanceof RpcError && e.code === -32601) {
      console.info("[gba-rpc] (not supported)", req.method, "-", e.message);
      return { error: { code: e.code, message: e.message, data: e.data } };
    }
    console.error("[gba-rpc] !!", req.method, "FAILED:", e);
    if (e instanceof RpcError) {
      return { error: { code: e.code, message: e.message, data: e.data } };
    }
    return {
      error: { code: -32603, message: e instanceof Error ? e.message : String(e) },
    };
  }
}

async function dispatch(origin: string, req: RpcRequest): Promise<unknown> {
  switch (req.method) {
    case "eth_accounts":
      return await ethAccounts(origin);
    case "eth_requestAccounts":
      return await ethRequestAccounts(origin);
    case "eth_chainId": {
      // Best-effort opportunistic refresh; the result arrives via a
      // chainChanged event if the network changed in the meantime.
      maybeRefreshPolicyInBg().catch(() => {});
      const net = await getActiveNetwork();
      return net.chainIdHex;
    }
    case "net_version": {
      maybeRefreshPolicyInBg().catch(() => {});
      const net = await getActiveNetwork();
      return String(net.chainId);
    }
    case "wallet_switchEthereumChain":
      return await walletSwitchChain((req.params as any)[0]);
    case "wallet_addEthereumChain":
      return await walletAddChain((req.params as any)[0]);
    case "wallet_watchAsset":
      return true;   // acknowledged, but we keep no token UI
    case "wallet_requestPermissions":
      return await walletRequestPermissions(origin, (req.params as any) ?? []);
    case "wallet_getPermissions":
      return await walletGetPermissions(origin);
    case "wallet_revokePermissions":
      return await walletRevokePermissions(origin, (req.params as any) ?? []);
    case "personal_sign":
      return await personalSign(origin, req.params as [Hex, Address]);
    case "eth_sign":
      throw new RpcError(-32601, "eth_sign disabled for safety; use personal_sign");
    case "eth_signTypedData_v4":
      return await ethSignTypedData(origin, req.params as [Address, string]);
    case "eth_sendTransaction":
      return await ethSendTransaction(origin, (req.params as any)[0]);
    case "eth_signTransaction":
      return await ethSignTransaction(origin, (req.params as any)[0]);
    default:
      // wallet_* methods are for the wallet, NOT for the chain's public
      // RPC. If they reach here it means we don't support them: reject
      // explicitly instead of forwarding to an RPC that would return
      // 401/-32601 and confuse the dApp. Unknown eth_* methods DO get
      // forwarded (eth_call, eth_getLogs, etc. are legit chain calls).
      if (req.method.startsWith("wallet_")) {
        throw new RpcError(-32601, `Method ${req.method} not supported by Coldpakku.`);
      }
      return await forwardRpc(req.method, (req.params as any) ?? []);
  }
}

async function forwardRpc(method: string, params: unknown[]): Promise<unknown> {
  const net = await getActiveNetwork();
  return await rpcCall(net, method, params);
}

// Re-exports so service-worker.ts keeps its import path stable.
export { connectAndCacheAddress, refreshGbaPolicy };
