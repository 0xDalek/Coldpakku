# Coldpakku v0.3.1

Coldpakku is an Ethereum hardware wallet that runs
on a Game Boy Advance. The GBA holds the 12-word BIP-39 seed in encrypted
SRAM, parses transactions on-device, and approves them with a physical
button press. A Raspberry Pi Pico bridges the GBA link cable to USB; a
Chromium extension exposes the wallet to any dApp via EIP-1193 + EIP-6963.

## Three downloads, three places

| Artifact | Where it goes |
|---|---|
| `coldpakku-v0.3.1.gba`               | Copy to your flashcart's SD card (~205 KB). |
| `coldpakku-pico-bridge-v0.3.1.zip`   | Unzip; follow the included `README.txt` (5 min). |
| `coldpakku-extension-v0.3.1.zip`     | Unzip; load via `chrome://extensions/` → Developer mode → **Load unpacked**. |

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

- **v0.3.1 fix — integer overflow in the on-device ABI decoder.** A
  crafted dynamic-type offset near `UINT32_MAX` made the bound check
  `offset + 32 > args_len` wrap, allowing a small out-of-bounds read
  from attacker-controlled calldata *before* the user approves. On the
  GBA (no MMU) the impact was a likely crash/misrender rather than
  disclosure, but it was a real memory-safety bug reachable from an
  untrusted bridge. Fixed with overflow-safe bound checks in
  `src/crypto/abi_decoder.c`. **Upgrade from v0.3.0.**
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

### Native ABI calldata decoder (v0.3)

`eth_sendTransaction` calldata is now decoded **on the cartridge**, not
just shown as raw hex. The firmware carries a hardcoded selector table
(`src/crypto/abi_selectors.c`, 25 entries) and a generic head/tail ABI
walker (`src/crypto/abi_decoder.c`) that produces a flat, indented
parsed view in the same style as the v0.2 EIP-712 parser. The wire
protocol does NOT change — the GBA decodes from the RLP bytes it
already parses for the signing hash, so a compromised host cannot
mislabel a call.

What's covered today:

- **ERC-20**: `transfer`, `approve` (with `MAX (infinite)`),
  `transferFrom`, `mint`, `burn`.
- **ERC-721 / ERC-1155**: `safeTransferFrom` (with and without `bytes`
  payload), `setApprovalForAll` (marked **drainer-grade**).
- **WETH**: `deposit()` and `withdraw(uint256)`.
- **ERC-2612 Permit**: `permit(...)`.
- **Uniswap V2 router**: all six `swap*` variants (with `address[]`
  path rendered as `N hops` + first three addresses), `addLiquidity*`,
  `removeLiquidity*`.
- **Wrappers**: `multicall(bytes[])`, `multicall(uint256,bytes[])`,
  Universal Router `execute(bytes,bytes[],uint256)`,
  `execute(bytes,bytes[])` — decoded **top-level only**: the user
  sees `commands: N sub-cmd`, `inputs: N sub-cmds`, `deadline: ...`
  without descending into the inner payload.
- **Atomic ABI types**: `address`, `bool`, `uint8..256`, `int256`,
  `bytes4`, `bytes32`, dynamic `bytes`, `string`, and `address[]`.

What still falls back to the v0.2 hex view (transparent — no UX
regression):

- Unknown selectors (anything not in the 25-entry table).
- Functions whose args use tuples or non-`address[]` dynamic arrays
  (Uniswap V3 `exactInputSingle` and similar). v0.4 will add a
  per-protocol plugin system to cover those.

UX: if the selector is recognised, page 0 (header) gets a `data:
<funcname>` hint plus an `R parsed >` status bar instead of
`R data >`. Pressing `R` once shows the parsed page; pressing again
walks through the legacy hex pages, exactly like v0.2.

### Browser extension (Manifest V3, ~5 300 LOC)

- EIP-1193 + EIP-6963 provider published as **Coldpakku**.
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
  source and verify the resulting `coldpakku.gba` SHA-256 matches the
  public release.
- **No secure element** — the GBA has no MMU, NX, ASLR, or stack
  canaries. A memory-corruption bug in our parsers would be terminal,
  and there is no defence-in-depth to contain one. Bounds-checking is
  applied consistently, but it is the *only* line of defence (one such
  overflow was found and fixed in v0.3.1; see Security above). Audit
  the parsers before trusting this with meaningful funds.
- **Extension not on the Chrome Web Store yet.** Install via
  "Load unpacked".
- **No native UF2 firmware for the Pico** — you must flash MicroPython
  (drag-and-drop UF2) and then copy `main.py`. See the Pico quickstart.
- **EIP-2930 (access list type 1) not implemented** — EIP-1559 (type 2)
  and legacy work.
- **EIP-712 blind signing is the largest residual attack surface.**
  Typed data the on-device parser cannot handle — anything with arrays
  (Permit2 `PermitBatch`, OpenSea Seaport orders), or when the host
  sends no TLV tree — falls back to **blind signing**: the device signs
  the host-supplied `domainSeparator` / `messageHash` and displays the
  host-supplied text, with **no on-device verification and no
  chain-lock enforcement**. Off-chain signatures (Permit / Permit2 /
  Seaport) are the dominant wallet-drainer vector today, so a
  compromised host can show benign text while you blind-sign a draining
  permit. The device shows a "could NOT parse — trust the host"
  warning, and for the *supported* subset it recomputes the hashes and
  hard-blocks on mismatch. Atomic types, strings, dynamic bytes and
  nested structs are covered; expanding to arrays + a hold-to-sign
  gesture for blind typed data is on the roadmap.
- **`eth_sendTransaction` selectors outside the v0.3 table are
  blind-signed.** The 25-entry on-device table covers ERC-20,
  ERC-721 `setApprovalForAll`, WETH, ERC-2612 Permit, Uniswap V2
  router, multicall and Universal Router top-level. Functions whose
  args use tuples (Uniswap V3 `exactInputSingle`, NFT marketplace
  orders) or non-`address[]` dynamic arrays still fall back to the
  hex view; the per-protocol plugin system in v0.4 will close that
  gap.
- **Single account** — derivation path is fixed to `m/44'/60'/0'/0/0`.
- **BIP-39 passphrase ("25th word") not exposed in the UI.**
- **PIN attempt counter is per-session**, not persisted across boots.
- **Weak resistance to physical theft of the cartridge.** The 3-strike
  SRAM wipe is an on-device control only. Anyone who dumps SRAM (easy
  with a flashcart) gets `salt ‖ nonce ‖ enc_seed ‖ MAC` and can
  brute-force the PIN offline against the MAC — no rate limit, no wipe.
  PBKDF2-HMAC-SHA512 × 10 000 is ~milliseconds per guess on a PC and
  the PIN is only 4–8 digits, so a 4-digit PIN falls in **seconds** and
  the full 8-digit space in **minutes** on commodity hardware. The
  encrypted seed in SRAM should be treated as offering little
  protection once the cartridge is in an attacker's hands. Argon2id /
  higher iteration counts / longer-or-alphanumeric PINs are on the
  roadmap; until then, keep the cartridge physically secure.

## Roadmap

Short list of what comes next, roughly in priority order:

1. **v0.4 — Decoder plugin system for complex routers.** Per-protocol
   sub-decoders (Universal Router commands, 1inch swap descriptions,
   0x assembly batches, Curve / Balancer routers, LiFi bridges).
   Mirrors the Ledger Live plugin model: one plugin per dApp router.
   Builds on the v0.3 generic ABI decoder by letting each plugin
   describe what's inside the `bytes`/`bytes[]` blobs the wrapper
   decoders currently render as `N sub-cmd`.
2. **EIP-712 array support** in the on-device parser so Permit2
   `PermitBatch` and Seaport orders can also be verified on-device
   instead of falling back to blind sign.
3. **Real-hardware testing on Ethereum mainnet** (only Polygon mainnet
   and Sepolia tested so far).
4. **Signed firmware** — show a SHA-256 of the running ROM at boot so
   the user can compare visually against the public release.
5. **Native UF2 firmware for the Pico** so step 1 of the Pico
   quickstart becomes "drag this `.uf2`" — no MicroPython, no
   `mpremote`. Probably `pico-sdk` + `tinyusb` CDC.
6. **Chrome Web Store listing**.
7. **Multi-account** screen (`m/44'/60'/0'/0/N`) and optional BIP-39
   passphrase.
8. **Persistent PIN failure counter** in SRAM (today the 3-strikes
   counter is per-session).
9. **Argon2id KDF** — strictly better than PBKDF2 against ASIC
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
