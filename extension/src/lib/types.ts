// Types shared across the whole extension.

export type Hex = `0x${string}`;
export type Address = Hex;

/** EIP-1559 transaction the extension builds before sending it to the GBA. */
export interface Eip1559Tx {
  type: 2;
  chainId: number;
  nonce: number;
  maxPriorityFeePerGas: bigint;
  maxFeePerGas: bigint;
  gas: bigint;
  to: Address | null;          // null = contract creation
  value: bigint;
  data: Uint8Array;            // raw bytes (no 0x prefix)
  accessList: AccessListItem[];
}

/** Legacy / EIP-155 transaction (type=0). */
export interface LegacyTx {
  type: 0;
  chainId: number;
  nonce: number;
  gasPrice: bigint;
  gas: bigint;
  to: Address | null;
  value: bigint;
  data: Uint8Array;
}

export type SignableTx = Eip1559Tx | LegacyTx;

export interface AccessListItem {
  address: Address;
  storageKeys: Hex[];
}

/** A network configured in the extension. */
export interface NetworkInfo {
  chainId: number;
  chainIdHex: Hex;
  name: string;
  rpcUrls: string[];
  nativeCurrency: { name: string; symbol: string; decimals: number };
  blockExplorerUrls?: string[];
}

/** Messages exchanged between injected-provider, content-script and service-worker. */
export type RpcRequest =
  | { method: "eth_accounts"; params?: [] }
  | { method: "eth_requestAccounts"; params?: [] }
  | { method: "eth_chainId"; params?: [] }
  | { method: "net_version"; params?: [] }
  | { method: "wallet_switchEthereumChain"; params: [{ chainId: Hex }] }
  | { method: "wallet_addEthereumChain"; params: [NetworkInfo] }
  | { method: "wallet_watchAsset"; params: { type: string; options: any } }
  | { method: "personal_sign"; params: [Hex, Address] }
  | { method: "eth_sign"; params: [Address, Hex] }
  | {
      method: "eth_signTypedData_v4";
      params: [Address, string];           // [address, JSON typed data]
    }
  | { method: "eth_sendTransaction"; params: [TxRequest] }
  | { method: "eth_signTransaction"; params: [TxRequest] }
  | { method: string; params?: any };       // fallback: forward to the RPC

export interface TxRequest {
  from?: Address;
  to?: Address;
  value?: Hex;
  data?: Hex;
  gas?: Hex;
  gasPrice?: Hex;
  maxFeePerGas?: Hex;
  maxPriorityFeePerGas?: Hex;
  nonce?: Hex;
  chainId?: Hex;
  type?: Hex;
}

/** EIP-1193 events the provider emits to the dApp. */
export type ProviderEvent =
  | { type: "accountsChanged"; data: Address[] }
  | { type: "chainChanged"; data: Hex }
  | { type: "disconnect"; data: { code: number; message: string } };
