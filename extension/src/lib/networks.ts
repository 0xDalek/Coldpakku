// List of Ethereum networks supported out of the box.
// The user can add more via wallet_addEthereumChain (persisted in
// chrome.storage.local). For public RPCs we pick endpoints with no API
// key by default; the user can swap in a keyed one if they want a
// better rate limit.
//
// ORDER: the popup dropdown iterates linearly, so we put:
//   1) Mainnets sorted by TVL/popularity
//   2) ALL testnets grouped at the end, with a suffix or clear name
//
// Matches the order in src/ui/chains.c on the GBA, so the cartridge's
// L/R selector and this dropdown navigate in the same order.

import type { NetworkInfo } from "./types";

export const DEFAULT_NETWORKS: NetworkInfo[] = [
  // === MAINNETS (sorted by popularity ~2026) ===============================
  {
    chainId: 1,
    chainIdHex: "0x1",
    name: "Ethereum Mainnet",
    rpcUrls: ["https://eth.llamarpc.com", "https://ethereum-rpc.publicnode.com"],
    nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
    blockExplorerUrls: ["https://etherscan.io"],
  },
  {
    chainId: 137,
    chainIdHex: "0x89",
    name: "Polygon",
    rpcUrls: ["https://polygon-rpc.com", "https://polygon-bor-rpc.publicnode.com"],
    nativeCurrency: { name: "POL", symbol: "POL", decimals: 18 },
    blockExplorerUrls: ["https://polygonscan.com"],
  },
  {
    chainId: 8453,
    chainIdHex: "0x2105",
    name: "Base",
    rpcUrls: ["https://mainnet.base.org", "https://base.llamarpc.com"],
    nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
    blockExplorerUrls: ["https://basescan.org"],
  },
  {
    chainId: 42161,
    chainIdHex: "0xa4b1",
    name: "Arbitrum One",
    rpcUrls: ["https://arb1.arbitrum.io/rpc", "https://arbitrum-one-rpc.publicnode.com"],
    nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
    blockExplorerUrls: ["https://arbiscan.io"],
  },
  {
    chainId: 10,
    chainIdHex: "0xa",
    name: "OP Mainnet",
    rpcUrls: ["https://mainnet.optimism.io", "https://optimism-rpc.publicnode.com"],
    nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
    blockExplorerUrls: ["https://optimistic.etherscan.io"],
  },
  {
    chainId: 56,
    chainIdHex: "0x38",
    name: "BNB Smart Chain",
    rpcUrls: ["https://bsc-dataseed.bnbchain.org", "https://bsc-rpc.publicnode.com"],
    nativeCurrency: { name: "BNB", symbol: "BNB", decimals: 18 },
    blockExplorerUrls: ["https://bscscan.com"],
  },
  {
    chainId: 43114,
    chainIdHex: "0xa86a",
    name: "Avalanche C-Chain",
    rpcUrls: [
      "https://api.avax.network/ext/bc/C/rpc",
      "https://avalanche-c-chain-rpc.publicnode.com",
    ],
    nativeCurrency: { name: "Avalanche", symbol: "AVAX", decimals: 18 },
    blockExplorerUrls: ["https://snowtrace.io"],
  },
  {
    chainId: 324,
    chainIdHex: "0x144",
    name: "zkSync Era",
    rpcUrls: ["https://mainnet.era.zksync.io", "https://zksync.drpc.org"],
    nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
    blockExplorerUrls: ["https://explorer.zksync.io"],
  },
  {
    chainId: 59144,
    chainIdHex: "0xe708",
    name: "Linea",
    rpcUrls: ["https://rpc.linea.build", "https://linea.drpc.org"],
    nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
    blockExplorerUrls: ["https://lineascan.build"],
  },
  {
    chainId: 534352,
    chainIdHex: "0x82750",
    name: "Scroll",
    rpcUrls: ["https://rpc.scroll.io", "https://scroll.drpc.org"],
    nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
    blockExplorerUrls: ["https://scrollscan.com"],
  },
  {
    chainId: 81457,
    chainIdHex: "0x13e31",
    name: "Blast",
    rpcUrls: ["https://rpc.blast.io", "https://blast.drpc.org"],
    nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
    blockExplorerUrls: ["https://blastscan.io"],
  },
  {
    chainId: 5000,
    chainIdHex: "0x1388",
    name: "Mantle",
    rpcUrls: ["https://rpc.mantle.xyz", "https://mantle.drpc.org"],
    nativeCurrency: { name: "Mantle", symbol: "MNT", decimals: 18 },
    blockExplorerUrls: ["https://explorer.mantle.xyz"],
  },
  {
    chainId: 100,
    chainIdHex: "0x64",
    name: "Gnosis Chain",
    rpcUrls: ["https://rpc.gnosischain.com", "https://gnosis.drpc.org"],
    nativeCurrency: { name: "xDAI", symbol: "xDAI", decimals: 18 },
    blockExplorerUrls: ["https://gnosisscan.io"],
  },

  // === TESTNETS (all grouped at the end) ===================================
  {
    chainId: 11155111,
    chainIdHex: "0xaa36a7",
    name: "Sepolia (test)",
    // Preferred order: publicnode (CDN, reliable) first. 1rpc.io has a
    // per-IP rate limit that runs out quickly; rpc.sepolia.org returns
    // 404 frequently. If publicnode + drpc fail, the older ones stay as
    // a final fallback.
    rpcUrls: [
      "https://ethereum-sepolia-rpc.publicnode.com",
      "https://sepolia.drpc.org",
      "https://1rpc.io/sepolia",
      "https://rpc.sepolia.org",
    ],
    nativeCurrency: { name: "Sepolia Ether", symbol: "ETH", decimals: 18 },
    blockExplorerUrls: ["https://sepolia.etherscan.io"],
  },
  {
    chainId: 84532,
    chainIdHex: "0x14a34",
    name: "Base Sepolia (test)",
    rpcUrls: ["https://sepolia.base.org", "https://base-sepolia.drpc.org"],
    nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
    blockExplorerUrls: ["https://sepolia.basescan.org"],
  },
  {
    chainId: 421614,
    chainIdHex: "0x66eee",
    name: "Arbitrum Sepolia (test)",
    rpcUrls: [
      "https://sepolia-rollup.arbitrum.io/rpc",
      "https://arbitrum-sepolia.drpc.org",
    ],
    nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
    blockExplorerUrls: ["https://sepolia.arbiscan.io"],
  },
  {
    chainId: 11155420,
    chainIdHex: "0xaa37dc",
    name: "OP Sepolia (test)",
    rpcUrls: [
      "https://sepolia.optimism.io",
      "https://optimism-sepolia.drpc.org",
    ],
    nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
    blockExplorerUrls: ["https://sepolia-optimism.etherscan.io"],
  },
  {
    chainId: 80002,
    chainIdHex: "0x13882",
    name: "Polygon Amoy (test)",
    rpcUrls: [
      "https://rpc-amoy.polygon.technology",
      "https://polygon-amoy.drpc.org",
    ],
    nativeCurrency: { name: "POL", symbol: "POL", decimals: 18 },
    blockExplorerUrls: ["https://amoy.polygonscan.com"],
  },
  {
    chainId: 97,
    chainIdHex: "0x61",
    name: "BSC Testnet (test)",
    rpcUrls: ["https://data-seed-prebsc-1-s1.bnbchain.org:8545"],
    nativeCurrency: { name: "tBNB", symbol: "tBNB", decimals: 18 },
    blockExplorerUrls: ["https://testnet.bscscan.com"],
  },
];

export function findNetworkByChainId(
  chainId: number | string,
  extraNetworks: NetworkInfo[] = [],
): NetworkInfo | undefined {
  const id = typeof chainId === "string" ? parseInt(chainId, 16) : chainId;
  return [...DEFAULT_NETWORKS, ...extraNetworks].find((n) => n.chainId === id);
}
