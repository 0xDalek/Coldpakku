// Read-only forwarder of JSON-RPC methods to the public RPC of the
// active network. Covers everything a dApp can ask for that does NOT
// require a signature:
//   eth_call, eth_getBalance, eth_blockNumber, eth_getCode, eth_getLogs,
//   eth_estimateGas, eth_getTransactionByHash, eth_getTransactionReceipt,
//   eth_gasPrice, eth_feeHistory, eth_maxPriorityFeePerGas, etc.
//
// We also use it internally to build a tx (nonce, gas, fees) and to run
// eth_sendRawTransaction after signing.

import type { NetworkInfo } from "../lib/types";

let nextId = 1;

export class RpcError extends Error {
  constructor(public code: number, message: string, public data?: unknown) {
    super(message);
  }
}

/** Calls a JSON-RPC method against `net.rpcUrls` with failover. */
export async function rpcCall(
  net: NetworkInfo,
  method: string,
  params: unknown[],
): Promise<any> {
  let lastErr: Error | null = null;
  for (const url of net.rpcUrls) {
    const t0 = performance.now();
    try {
      const result = await rpcCallSingle(url, method, params);
      const dt = Math.round(performance.now() - t0);
      console.debug(`[rpc] ${hostOf(url)} ${method} OK ${dt}ms (chain ${net.chainId})`);
      return result;
    } catch (e) {
      const dt = Math.round(performance.now() - t0);
      console.debug(`[rpc] ${hostOf(url)} ${method} FAIL ${dt}ms:`, e instanceof Error ? e.message : e);
      lastErr = e instanceof Error ? e : new Error(String(e));
    }
  }
  throw lastErr ?? new Error("no RPC answered");
}

function hostOf(url: string): string {
  try { return new URL(url).host; } catch { return url; }
}

async function rpcCallSingle(url: string, method: string, params: unknown[]): Promise<any> {
  const body = JSON.stringify({
    jsonrpc: "2.0",
    id: nextId++,
    method,
    params,
  });
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body,
  });
  if (!res.ok) throw new Error(`HTTP ${res.status} on ${method}`);
  const j = await res.json();
  if (j.error) {
    throw new RpcError(j.error.code ?? -32000, j.error.message ?? "rpc error", j.error.data);
  }
  return j.result;
}
