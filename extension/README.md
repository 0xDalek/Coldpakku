# Coldpakku browser extension

Chromium-based extension (Manifest V3) that turns a Game Boy Advance into
an Ethereum hardware wallet for any web dApp. Announces itself via
EIP-6963 only — coexists with MetaMask / Rabby in the dApp wallet
picker without overriding `window.ethereum`.

## Architecture

```
dApp ── window.ethereum (EIP-1193 + EIP-6963) ── injected-provider
                                                       │
                                            window.postMessage
                                                       │
                                              content-script
                                                       │
                                            chrome.runtime
                                                       │
                                          service-worker (MV3)
                                          ├── methods/ (dispatch by category)
                                          ├── offscreen page
                                          │      └── WebSerial → Pico USB-CDC → GBA
                                          └── fetch → public RPC of active chain
                                                      (+ user overrides from
                                                       chrome.storage.local)
```

The extension is a dumb bridge: all key material stays in the GBA. The
service worker builds RLP / EIP-712 payloads, ships them to the GBA for
signing through the offscreen document (the only context allowed to use
`navigator.serial` in MV3), and posts the signature back to the dApp (or
broadcasts it via the active chain's RPC).

Source tree (~5 300 LOC):

```
src/
├── background/
│   ├── service-worker.ts        # MV3 entry + message bus
│   ├── provider-handler.ts      # thin dispatcher (~90 LOC)
│   ├── methods/                 # split by category (audit-friendly)
│   │   ├── accounts.ts          # eth_accounts + EIP-2255 permissions
│   │   ├── chain.ts             # chainId, switchChain, policy refresh
│   │   ├── sign.ts              # personal_sign, signTypedData_v4
│   │   ├── tx.ts                # sendTransaction, signTransaction
│   │   └── _shared.ts           # cross-method helpers
│   ├── session.ts               # chrome.storage state (address, RPC overrides)
│   ├── serial-bridge.ts         # SW → offscreen relay + SW-side mutex
│   ├── rpc-passthrough.ts       # JSON-RPC HTTP fanout with failover
│   ├── confirm-orchestrator.ts  # pending-request state for popup
│   ├── sig-recover.ts           # recid recovery (v=27/28)
│   └── protocol.ts              # opcode constants
├── offscreen/serial.ts          # WebSerial owner: port + protocol + heartbeat
├── content/
│   ├── injected-provider.ts     # EIP-1193 + EIP-6963 announce
│   └── content-script.ts        # postMessage relay
├── popup/                       # toolbar icon UI
├── confirm/                     # detached "what is being signed" view
├── connect/                     # port-pick page (popup loses focus otherwise)
├── options/                     # settings page (custom RPCs per chain)
└── lib/                         # pure data: rlp, eip712, networks, hex,
                                 # keccak, address, selectors, tx_meta, types
```

## Supported provider methods (EIP-1193)

| Method                          | Backend |
|---------------------------------|---------|
| `eth_accounts`                  | local cache (returns `[]` if origin not authorized) |
| `eth_requestAccounts`           | first-visit prompt on the GBA (origin + A/B), cached afterwards |
| `wallet_requestPermissions`     | EIP-2255 — reuses the same connect flow as above |
| `wallet_getPermissions`         | EIP-2255 — list of currently granted permissions |
| `wallet_revokePermissions`      | EIP-2255 — drop an origin from the authorized set |
| `eth_chainId`, `net_version`    | active network state (driven by the GBA chain lock) |
| `wallet_switchEthereumChain`    | if mismatch, returns 4902 telling the dApp to switch on the GBA |
| `wallet_addEthereumChain`       | persists custom net to `chrome.storage.local` |
| `wallet_watchAsset`             | no-op (acknowledged) |
| `personal_sign`                 | GBA `PROTO_PERSONAL_SIGN` (0xD0) — message hashed on-device |
| `eth_signTypedData_v4`          | GBA `PROTO_TYPED_DATA` (0xD1) — host hashes, GBA shows text + truncated hashes |
| `eth_sendTransaction`           | GBA `PROTO_TX_RLP_META` (0xD2) + RPC broadcast |
| `eth_signTransaction`           | GBA `PROTO_TX_RLP_META` (0xD2), no broadcast — raw hex returned |
| `eth_sign`                      | rejected (use `personal_sign`) |
| any unknown `wallet_*`          | rejected with -32601 (so dApp falls back to legacy flow) |
| anything else                   | forwarded to the active chain RPC |

## Default networks

12 mainnets (Ethereum, Polygon, Base, Arbitrum, OP, BSC, Avalanche,
zkSync Era, Linea, Scroll, Blast, Mantle, Gnosis) plus 6 testnets
(Sepolia, Base Sepolia, Arb Sepolia, OP Sepolia, Polygon Amoy, BSC
Testnet).

Each ships with two public RPC URLs (publicnode / llamarpc / official
endpoints). The user can **prepend their own RPC URLs per chain** in the
settings page (popup → footer → "settings"). User URLs are tried first
with the public defaults as automatic fallback (so a flaky private node
doesn't break the wallet). Includes a "Test" button that fires
`eth_blockNumber` and reports latency.

The user can also add fully new chains via the standard
`wallet_addEthereumChain`.

## Build

```bash
cd extension
npm install
npm run build      # outputs dist/
```

## Install (developer mode)

1. Build the extension (above).
2. Open `chrome://extensions/`, enable **Developer mode** (top right).
3. Click **Load unpacked** and select the `extension/dist/` folder.
4. Flash the Pico bridge — see [`../docs/PICO_BRIDGE_QUICKSTART.md`](../docs/PICO_BRIDGE_QUICKSTART.md).
5. Flash the GBA ROM — copy `../coldpakku.gba` to your flashcart (or
   run in mGBA).
6. Boot the GBA, enter your PIN, plug the Pico via USB.
7. Click the extension icon in Chrome, hit **Connect GBA**, authorize
   the USB-CDC port (it appears as Raspberry Pi Pico, VID 0x2E8A).
8. Visit any dApp that supports EIP-6963 (Uniswap, Aave, OpenSea
   modern, …) and pick **Coldpakku** in its wallet picker.

## Security notes

- **Private keys never leave the GBA.** The seed is encrypted in SRAM
  with ChaCha20 under a key derived from the PIN via PBKDF2-HMAC-SHA512
  (10 000 iterations) with a 16-byte random salt. HMAC-SHA256 is used to
  authenticate the blob — a wrong PIN is rejected without decrypting.
- **Transactions are decoded on-device** from raw RLP — the bridge
  cannot show one `to`/`value` and sign a different one.
- **Per-origin connect approval lives on the cartridge.** The very first
  request from each origin (Uniswap, Aave, …) is approved on the GBA
  with A/B; the decision is cached afterwards in `chrome.storage.local`.
- **`personal_sign` is hashed on the GBA itself** with the EIP-191
  prefix — host can't redirect the signature.
- **`eth_signTypedData_v4` is blind-signed** by the GBA today (host
  pre-computes the hashes). To mitigate, the GBA shows the human text
  the host claims, plus the truncated `domainSeparator` / `messageHash`
  in hex for manual verification. Native EIP-712 parsing is on the
  roadmap.
- The signing approval requires pressing **A on the GBA** — a
  compromised browser cannot approve without you seeing the parsed
  fields on the cartridge screen.
- **Chain lock** — the active chain is set on the GBA with `L/R`. Any
  transaction for a different chainId is rejected on-device and the
  dApp gets a standard 4901 error.
- **Custom RPC privacy warning** — whatever RPC URL you configure will
  see your balance queries and broadcasted signed txs. For full privacy
  run your own node and point the override there.

## Development

```bash
npm run dev        # Vite dev server with HMR
npm run typecheck  # tsc --noEmit
npm run build      # production bundle to dist/
```

Service-worker logs come out in the `chrome://extensions/` → "service
worker" DevTools (set the level dropdown to include **Verbose** to see
the per-RPC `[rpc]` traces). Set `[gba-rpc]` filter to focus on the
EIP-1193 method dispatch only.
