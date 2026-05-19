// Handlers for eth_accounts and eth_requestAccounts + the connect flow
// (popup -> request port -> store address).

import type { Address } from "../../lib/types";
import { toChecksumAddress } from "../../lib/address";
import { RpcError } from "../rpc-passthrough";
import { withGbaSession } from "../serial-bridge";
import {
  authorizeOrigin,
  isAuthorized,
  loadState,
  revokeOrigin,
  setAddress,
  setGbaPolicyChainId,
} from "../session";

export async function ethAccounts(origin: string): Promise<Address[]> {
  if (!(await isAuthorized(origin))) return [];
  const s = await loadState();
  return s.addressChecksum ? [s.addressChecksum] : [];
}

export async function ethRequestAccounts(origin: string): Promise<Address[]> {
  const s = await loadState();
  if (!s.addressChecksum) {
    throw new RpcError(
      4100,
      "Coldpakku is not connected. Open the popup and press 'Connect GBA'.",
    );
  }

  // If the origin was already approved on a previous visit, return the
  // address without bothering the user again (per-origin permission cache).
  if (await isAuthorized(origin)) {
    return [s.addressChecksum];
  }

  // First time for this origin: ask for confirmation ON THE GBA. Stays
  // consistent with "the GBA is the authority" — we do not auto-approve
  // on the host. The user sees the dApp's origin on screen and presses
  // A or B; the decision is cached in chrome.storage.local.
  let approved: boolean;
  try {
    approved = await withGbaSession((session) => session.requestConnect(origin));
  } catch (e) {
    throw new RpcError(
      4100,
      `Could not ask the GBA for approval: ${e instanceof Error ? e.message : String(e)}`,
    );
  }

  if (!approved) {
    // EIP-1193 code 4001: User rejected the request.
    throw new RpcError(4001, `Connection denied by the user on the GBA.`);
  }

  await authorizeOrigin(origin);
  return [s.addressChecksum];
}

// ============================================================================
// EIP-2255: wallet_requestPermissions / wallet_getPermissions
// ============================================================================
//
// Modern dApps (Uniswap, etc.) use these instead of eth_requestAccounts
// directly. The extension only supports the "eth_accounts" caveat (read
// access to the address). Any other permission requested is rejected.

interface Eip2255Permission {
  parentCapability: string;
  invoker?: string;
  caveats?: { type: string; value: unknown }[];
}

/** Builds the list of permissions currently granted to `origin`. */
async function permissionsFor(origin: string): Promise<Eip2255Permission[]> {
  const s = await loadState();
  if (!s.addressChecksum) return [];
  if (!(await isAuthorized(origin))) return [];
  return [
    {
      parentCapability: "eth_accounts",
      invoker: origin,
      caveats: [{ type: "restrictReturnedAccounts", value: [s.addressChecksum] }],
    },
  ];
}

/** wallet_requestPermissions: the dApp asks for capabilities. Today we
 *  only support `eth_accounts`. If the dApp asks for it and it is not
 *  yet approved for this origin, we reuse the same flow as
 *  eth_requestAccounts (CONNECT REQ screen on the GBA). */
export async function walletRequestPermissions(
  origin: string,
  params: any[],
): Promise<Eip2255Permission[]> {
  const requested = (params && params[0]) ?? {};
  // We only accept eth_accounts; dApps don't ask for anything else in
  // practice, and even if they did we wouldn't know what to do with it.
  const wantsEthAccounts = Object.prototype.hasOwnProperty.call(requested, "eth_accounts");
  if (!wantsEthAccounts) {
    throw new RpcError(
      -32601,
      `Coldpakku only supports the "eth_accounts" permission. You asked for: ${Object.keys(requested).join(", ") || "(nothing)"}.`,
    );
  }
  // Reuse the exact eth_requestAccounts flow: if already authorized
  // returns directly, otherwise asks on the GBA and persists.
  await ethRequestAccounts(origin);
  return await permissionsFor(origin);
}

/** wallet_getPermissions: returns current permissions without asking anything. */
export async function walletGetPermissions(origin: string): Promise<Eip2255Permission[]> {
  return await permissionsFor(origin);
}

/** wallet_revokePermissions (EIP-2255 ext): the dApp asks to disconnect.
 *  The GBA does not change; we just drop the origin from the authorized
 *  list. */
export async function walletRevokePermissions(
  origin: string,
  _params: any[],
): Promise<null> {
  await revokeOrigin(origin);
  return null;
}

/** Called from the popup after the user authorizes the port: reads
 *  address + policy in a single serial session and persists both. */
export async function connectAndCacheAddress(): Promise<{
  address: Address;
  policyChainId: number;
}> {
  const { addrBytes, policyChainId } = await withGbaSession(async (session) => {
    const a = await session.getAddress();
    let pol = 0;
    try {
      pol = await session.getPolicy();
    } catch {
      // GBA with old firmware (pre-v5) does not support GET_POLICY: leave 0.
    }
    return { addrBytes: a, policyChainId: pol };
  });
  const checksum = toChecksumAddress(addrBytes);
  await setAddress(addrBytes, checksum);
  await setGbaPolicyChainId(policyChainId).catch(() => {});
  return { address: checksum, policyChainId };
}
