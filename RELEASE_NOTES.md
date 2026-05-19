# GBA Signer v0.1.0

First public release of GBA Signer, an Ethereum hardware wallet that runs
on a Game Boy Advance. The GBA holds the 12-word BIP-39 seed in encrypted
SRAM, parses transactions on-device, and approves them with a physical
button press. A Raspberry Pi Pico bridges the GBA link cable to USB; a
Chromium extension exposes the wallet to any dApp via EIP-1193 + EIP-6963.

## Three downloads, three places

| Artifact | Where it goes |
|---|---|
| `gba-signer-v0.1.0.gba`              | Copy to your flashcart's SD card (~205 KB). |
| `gba-signer-pico-bridge-v0.1.0.zip`  | Unzip; follow the included `README.txt` (5 min). |
| `gba-signer-extension-v0.1.0.zip`    | Unzip; load via `chrome://extensions/` → Developer mode → **Load unpacked**. |

See the project [README](README.md) for the full first-use guide.

## What works end-to-end on real hardware

Tested on a physical GBA + Pi Pico + Chromium extension. Working flows:

- **dApp login** via EIP-2255 `wallet_requestPermissions` — Uniswap and
  other modern wagmi-based dApps.
- **`personal_sign`** (EIP-191) — Sign-In With Ethereum, message hashed
  on-device with the standard prefix.
- **`eth_signTypedData_v4`** (EIP-712) — Permit, Permit2, and other typed
  signatures. Hashes pre-computed by the host; the GBA shows the
  pretty-printed text *and* the truncated `domainSeparator` / `messageHash`
  for manual verification.
- **`eth_sendTransaction`** on Polygon mainnet — full Uniswap swap
  (approve + swap) broadcast end-to-end through our RPC layer.
- **Chain lock on the cartridge** — the user selects the active chain
  with `L/R` on the GBA. Any transaction for a different chainId is
  rejected on-device with a clear UI; the dApp gets a standard 4901
  error explaining how to switch.

## Highlights

### Security

- **PBKDF2-stretched PIN** — the seed is encrypted with ChaCha20 under
  a key derived via PBKDF2-HMAC-SHA512 (10 000 iterations) with a
  16-byte random salt. The cartridge blob includes an HMAC-SHA256 over
  `version ‖ salt ‖ nonce ‖ ciphertext` so a wrong PIN is **rejected
  without decrypting** — no "ghost wallet" pitfalls.
- **3 failed PIN attempts → SRAM wipe** (per-session).
- **SELECT → wipe wallet** — explicit hold-A-3-seconds confirmation
  on-device to deliberately erase the encrypted blob from SRAM (e.g.
  before reselling the cartridge).
- **Backward-compatible blob migration** — sessions saved with the old
  single-SHA256 KDF are upgraded to the new PBKDF2 blob on the next
  successful unlock, without forcing the user to re-enter the 12 words.
- 12 words and PIN never touch SRAM or UART, not even encrypted.
- Private key only in RAM; zeroized on power-off and on lock.
- RFC 6979 deterministic ECDSA — independent of the GBA's weak RNG.
- Low-S signature canonicalization on-device.

### On-device transaction parsing

The GBA decodes raw RLP itself — legacy and EIP-1559. It shows
`chainId`, `nonce`, `to` (EIP-55 mixed-case), `value`, `maxFeePerGas`,
`gas`, `data` length, and a 4-byte transaction ID so the user can match
what the extension shows against what the GBA is about to sign.

The bridge cannot lie about fields: the GBA computes the signing hash
itself from the bytes it parsed and displayed.

### ERC-20 / NFT decoder on-device

The GBA recognises the most common selectors and renders human text:

- `transfer(address,uint256)` and `transferFrom`
- `approve(address,uint256)` — with **INFINITE warning** for `MAX_UINT256`
- `safeTransferFrom` and `setApprovalForAll(address,bool)` (NFTs)
- WETH-style `deposit()` and `withdraw(uint256)` — shown as wrap/unwrap

Token symbols and decimals are forwarded by the extension via a small TLV
metadata block (along with the origin host) so the GBA can render
`-1.5 USDC +1.5 USDCe` instead of `-1500000 raw +1500000 raw`. No token
addresses are hard-coded in ROM.

### Native EIP-191

`personal_sign` is hashed on the GBA from the raw message bytes — no
precomputed hash from the host. A compromised browser cannot redirect
the signature to a different message.

### EIP-712 with on-device verification (v0.2 / wire v7)

For `eth_signTypedData_v4` the host always sends the precomputed
`domainSeparator` and `messageHash` plus a pretty-printed text *and* an
optional TLV serialization of the typed data (see
[docs/PROTOCOL.md](docs/PROTOCOL.md#typed_data-payload-v7)). New in v0.2:

1. **Parsed view is the default** whenever the cartridge could re-derive
   the hashes on-device. The user sees, without doing anything,
   `[TYPED DATA OK][PARSE]` with `<primaryType> chain:<id>`, a
   `hash MATCH` banner, and every field of `Domain` + the primary
   message in a flat, indented list (struct-aware up to depth 4).
2. **Hold `L+R`** to toggle to the legacy blind view (text + truncated
   hex hashes). Useful to eyeball the raw `domainSeparator` /
   `messageHash` against a trusted source if you want.
3. If the parser detects that the host's hashes do not match what the
   typed data hashes to (a tampered host), the confirm screen turns
   into a **HOST HASH MISMATCH** warning and signing is **blocked** —
   only cancel is honoured.
4. If `EIP712Domain.chainId` is present and does not match the
   cartridge's chain lock, the signature is rejected the same way as
   an off-chain tx (`PROTO_REJECT_CHAIN` + `WRONG CHAIN` screen),
   *before* the confirm screen is shown.
5. The parser detects the "infinite approval" sentinel (`uint*` value
   all-ones for ≥128 bits) and shows `MAX (infinite)` instead of the
   raw hex. Covers ERC-20 `approve(uint256 max)` and Permit2
   `PermitDetails.amount = uint160 max` as used by Uniswap.

Supported type subset (v0.2, matches Ledger's clear-signing without
plugins): atomic types (`address`, `bool`, `uint*`, `int*`, `bytes1..32`),
dynamic types (`string`, `bytes`), and nested structs up to depth 4.
Arrays (`T[]`, `T[N]`) cause the parser to refuse the parsed view; the
user gets the blind view directly (text + hex hashes) and can still
sign with `A`. The statusbar will not advertise `L+R` in that case.

### Browser extension (Manifest V3, ~5 300 LOC)

- EIP-1193 + EIP-6963 provider published as **GBA Signer**.
- Full coverage of the methods Uniswap and similar modern dApps use:
  - EIP-2255 `wallet_requestPermissions` / `wallet_getPermissions` /
    `wallet_revokePermissions`
  - `eth_requestAccounts`, `eth_accounts`, `eth_chainId`, `net_version`
  - `wallet_switchEthereumChain` / `wallet_addEthereumChain`
  - `personal_sign`, `eth_signTypedData_v4`
  - `eth_sendTransaction`, `eth_signTransaction`
  - `eth_sign` is **rejected** by design.
- **12 default chains** (mainnet, Polygon, Base, Arbitrum, Optimism,
  BSC, Avalanche, zkSync Era, Linea, Scroll, Blast, Mantle, Gnosis) plus
  6 testnets.
- **Custom RPC overrides per chain** via a settings page (popup → footer
  → "settings"). User URLs are tried first, public defaults are
  automatic fallback. Each entry has a one-click latency test. Config is
  stored in `chrome.storage.local` and can be exported / imported as
  JSON.
- **Per-origin connect approval on the cartridge** — first time a dApp
  asks for `eth_accounts`, the GBA shows the origin and waits for A/B.
  The decision is cached in extension storage.
- **Active-request UI in the popup** — when a signing request is in
  flight, the popup shows origin, address, decoded function, gas
  details, and the 4-byte TX ID the GBA will display. The user can
  cancel from there; the actual approval requires `A` on the cartridge.
- **5-second host heartbeat** with an explicit link indicator on the
  GBA (`OK / idle / OFFLINE`). Unplug is detected in ≤ 10 s.

### Pi Pico bridge

- Pure MicroPython (`pico/main.py`), 90 lines, no extra dependencies.
- 2-second rescue window after boot during which `Ctrl-C` still works
  in the REPL.
- See [`docs/PICO_BRIDGE_QUICKSTART.md`](docs/PICO_BRIDGE_QUICKSTART.md)
  for the end-user setup.

### GBA UI

- COLDPAKKU splash screen on boot (Mode 4 bitmap with palette fade).
- Orange-on-black phosphor terminal aesthetic. Amber and green schemes
  also available in `src/ui/text.c`.
- ASCII-art "cartridge label" banner with a real boot self-test (ROM
  header CRC, SRAM probe, uECC link check, keccak vector).
- Progress bar during the slow steps (BIP-39 PBKDF2, BIP-32 derivation,
  PBKDF2 PIN stretch).
- BIP-39 word picker that filters the 2048-word list by prefix as you
  type.
- AWAITING TX screen with: account, chain selector, link indicator,
  signed-this-session counter.
- Static "SIGNING…" screen during ECDSA so the user knows the 3–7 s
  freeze is expected.

## Known limitations

- **No firmware integrity check beyond the gbafix header CRC** — a
  modified cartridge could ship an "export_seed" opcode. Build from
  source and verify the resulting `gba-signer.gba` SHA-256 matches the
  public release.
- **No secure element** — the GBA has no MMU, NX, ASLR, or stack
  canaries. A memory-corruption bug in our parsers would be terminal.
  No such bug is known; bounds-checking is consistent throughout, but
  defence-in-depth is limited.
- **Extension not on the Chrome Web Store yet.** Install via
  "Load unpacked".
- **No native UF2 firmware for the Pico** — you must flash MicroPython
  (drag-and-drop UF2) and then copy `main.py`. See the Pico quickstart.
- **EIP-2930 (access list type 1) not implemented** — EIP-1559 (type 2)
  and legacy work.
- **EIP-712 arrays not supported by the on-device parser yet** —
  Permit2 `PermitBatch` and OpenSea Seaport orders fall back to blind
  signing of the host-supplied hashes (with the legacy warning).
  Atomic types, strings, dynamic bytes and nested structs are covered.
- **`eth_sendTransaction` calldata is blind-signed on-device** — the
  cartridge shows `to`, `value`, `chainId`, `gas` and the raw calldata
  hex, but does NOT decode ABI args. The "function: approve, spender:
  …, amount: infinite" labels you see come from the browser extension
  popup, which a compromised host could manipulate. v0.3 closes this
  gap with a native ABI decoder for the ~30 most common selectors
  (ERC-20, Permit, Uniswap V2/V3 swaps, multicall), mirroring what
  v0.2 did for EIP-712.
- **Single account** — derivation path is fixed to `m/44'/60'/0'/0/0`.
- **BIP-39 passphrase ("25th word") not exposed in the UI.**
- **PIN attempt counter is per-session**, not persisted across boots.

## Roadmap

Short list of what comes next, roughly in priority order:

1. **v0.3 — Native calldata decoder on the GBA.** Same idea as v0.2's
   EIP-712 parser, applied to `eth_sendTransaction`. The cartridge
   carries a hardcoded table of ~30 selectors (ERC-20, Permit, WETH,
   Uniswap V2/V3 swaps, multicall…) and decodes the calldata args
   on-device for atomic types (`address`, `uint*`, `int*`, `bytesN`,
   `bool`, `string`, `bytes`). Parsed view by default; **L+R** toggles
   to the raw hex. Unknown selectors fall back transparently to the
   current hex view. Top-level decode for wrapper functions
   (`execute`, `multicall`) without descending into their sub-payload.
2. **v0.4 — Decoder plugin system for complex routers.** Per-protocol
   sub-decoders (Universal Router commands, 1inch swap descriptions,
   0x assembly batches, Curve / Balancer routers, LiFi bridges).
   Mirrors the Ledger Live plugin model: one plugin per dApp router.
3. **EIP-712 array support** in the on-device parser so Permit2
   `PermitBatch` and Seaport orders can also be verified on-device
   instead of falling back to blind sign.
4. **Real-hardware testing on Ethereum mainnet** (only Polygon mainnet
   and Sepolia tested so far).
5. **Signed firmware** — show a SHA-256 of the running ROM at boot so
   the user can compare visually against the public release.
6. **Native UF2 firmware for the Pico** so step 1 of the Pico
   quickstart becomes "drag this `.uf2`" — no MicroPython, no
   `mpremote`. Probably `pico-sdk` + `tinyusb` CDC.
7. **Chrome Web Store listing**.
8. **Multi-account** screen (`m/44'/60'/0'/0/N`) and optional BIP-39
   passphrase.
9. **Persistent PIN failure counter** in SRAM (today the 3-strikes
   counter is per-session).
10. **Argon2id KDF** — strictly better than PBKDF2 against ASIC
    attackers, but expensive on ARM7TDMI.

## Build it yourself

```bash
git clone https://github.com/0xDalek/Coldpakku.git
cd Coldpakku
export DEVKITPRO=/path/to/devkitpro
export DEVKITARM=$DEVKITPRO/devkitARM
./scripts/build_release.sh
ls releases/
```

Outputs the same three artifacts plus a copy of these release notes.
