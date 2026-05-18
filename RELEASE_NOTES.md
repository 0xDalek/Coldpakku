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

### EIP-712 with manual verification

For `eth_signTypedData_v4` the GBA receives the precomputed
`domainSeparator` / `messageHash` from the extension (a native parser is
on the roadmap). To make this safer, the GBA displays:

1. The human-readable, pretty-printed structure that the host claims it
   built the hashes from (domain name, version, chainId, message).
2. The first / last bytes of both hashes for manual verification against
   the dApp.

If the host lied about the human text, the hashes don't match.

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

- **No native EIP-712 parser on the GBA** — today the cartridge
  blind-signs the hashes computed by the host. The pretty-printed text
  and the manual hash comparison are the mitigations.
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
- **Single account** — derivation path is fixed to `m/44'/60'/0'/0/0`.
- **BIP-39 passphrase ("25th word") not exposed in the UI.**
- **PIN attempt counter is per-session**, not persisted across boots.

## Roadmap

Short list of what comes next, roughly in priority order:

1. **Native EIP-712 parser on the GBA** so the cartridge stops trusting
   precomputed hashes for typed data — the largest remaining trust
   vector.
2. **Real-hardware testing on Ethereum mainnet** (only Polygon mainnet
   and Sepolia tested so far).
3. **Signed firmware** — show a SHA-256 of the running ROM at boot so
   the user can compare visually against the public release.
4. **Native UF2 firmware for the Pico** so step 1 of the Pico
   quickstart becomes "drag this `.uf2`" — no MicroPython, no
   `mpremote`. Probably `pico-sdk` + `tinyusb` CDC.
5. **Chrome Web Store listing**.
6. **Multi-account** screen (`m/44'/60'/0'/0/N`) and optional BIP-39
   passphrase.
7. **Persistent PIN failure counter** in SRAM (today the 3-strikes
   counter is per-session).
8. **Argon2id KDF** — strictly better than PBKDF2 against ASIC
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
