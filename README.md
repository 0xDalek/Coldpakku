# Coldpakku — Ethereum hardware wallet on Game Boy Advance

Use a Game Boy Advance as a physical device for signing Ethereum
transactions. The 12 BIP39 words never leave the GBA, and the private key
never leaves cartridge RAM. **The GBA parses the transaction itself**: the
bridge cannot show you a tidy `to` on screen and sign a different hash.

> Current status: **end-to-end working on real hardware**. ROM ~205 KB.
> Tested flows on physical GBA + Pico bridge + Chromium extension:
> - Connect & login on dApps via EIP-2255 `wallet_requestPermissions` (Uniswap, etc.)
> - `personal_sign` (EIP-191) — SIWE-style login
> - `eth_signTypedData_v4` (EIP-712) — Permit, Permit2
> - `eth_sendTransaction` on Polygon mainnet (Uniswap swap broadcast end-to-end)
> - Chain lock on cartridge: tx for wrong chainId is rejected on-device with a clear UI
>
> Algorithm parity verified against `eth_account` (`tests/algorithm_verify.py`)
> and RLP hash parity on 100 random txs (`tests/test_rlp_parity.py`).

## Install (no build tools required)

Three downloadable artifacts (no `npm`, no `make`, no devkitARM) — see
the [latest GitHub release](../../releases/latest):

| File | Where it goes |
|---|---|
| `gba-signer-v0.1.0.gba`              | Copy to your flashcart's SD card (EZ-Flash, EverDrive, etc.) |
| `gba-signer-pico-bridge-v0.1.0.zip`  | Unzip and follow [`docs/PICO_BRIDGE_QUICKSTART.md`](docs/PICO_BRIDGE_QUICKSTART.md) (5 min) |
| `gba-signer-extension-v0.1.0.zip`    | Unzip, then `chrome://extensions/` → Developer mode → **Load unpacked** → pick the unzipped folder |

### Hardware checklist

- A Game Boy Advance + flashcart with the ROM
- A Raspberry Pi Pico wired to a GBA link cable
  (3 wires — diagram in [`docs/PICO_BRIDGE.md`](docs/PICO_BRIDGE.md))
- A Chromium-based browser (Chrome, Edge, Brave, Arc — anything that
  supports WebSerial, MV3 and Chrome ≥ 115)

### First use (one-time setup)

1. Boot the GBA. Type your **12 BIP39 words** with the on-screen keyboard
   and pick a **PIN** (4–8 digits). Both stay encrypted in cartridge SRAM
   and never leave the GBA. The PIN is stretched with PBKDF2-HMAC-SHA512
   (10 000 iterations) — first unlock takes ~10 s, the bar shows progress.
   Subsequent boots just ask for the PIN.
2. Plug the Pico via USB.
3. Click the **GBA Signer** extension icon → **Connect GBA** → pick the
   Pico's serial port (it shows up as "USB Serial Device" or "Raspberry
   Pi Pico"). The choice is remembered, so you only do this once per
   browser profile.
4. Visit any dApp (Uniswap, Aave, OpenSea…) and pick **GBA Signer** in
   the wallet picker. The extension advertises itself via EIP-6963
   only — it does **not** override `window.ethereum`, so dApps that
   ignore EIP-6963 (PancakeSwap legacy, OpenSea legacy) will not see
   GBA Signer in their picker.
5. On the first request from each dApp, the **GBA shows a "CONNECT REQ"
   screen with the origin** (e.g. `app.uniswap.org`). Press **A** to
   allow, **B** to deny. The decision is cached in the extension; you
   only see this once per origin.

Every transaction or message asks for confirmation **on the GBA** (press
**A** to sign, **B** to cancel). The browser extension only shows what
is being signed; the actual approval lives on the cartridge.

### Cartridge buttons on the AWAITING TX screen

| Button | Action |
|---|---|
| `L` / `R` (or `LEFT` / `RIGHT` d-pad) | Switch the active chain. The chain lock persists in SRAM. |
| `START` | Lock the session: wipes the seed and private key from RAM. Requires PIN to come back. The encrypted blob in SRAM is preserved. |
| `SELECT` | **Wipe wallet** — opens a destructive confirmation screen. Requires holding `A` for 3 seconds (with on-screen progress bar) to actually erase the encrypted seed from SRAM. Any other key cancels. **Make sure you have your 12 BIP-39 words backed up before doing this.** |
| `A` / `B` on a confirm screen | Approve / reject the pending operation. |

### Custom RPCs (optional)

Default networks ship with public RPCs (publicnode, llamarpc, official
endpoints). Open the extension popup → **`settings`** to add your own
RPC URLs per chain (Alchemy, Infura, your own node…). Your URLs are
tried first, with the public ones as automatic fallback. Includes a
"Test" button that runs `eth_blockNumber` against the URL and reports
latency. Config is stored in `chrome.storage.local` and can be
exported/imported as JSON.

> Privacy note: whatever RPC you choose can see your balance queries
> and broadcasted signed txs. For full privacy run your own node and
> point the override there.

### Try it on mGBA (without real hardware)

```bash
# build the ROM (requires devkitARM — see "Build from source" below)
./build.sh
mgba -l 0.0.0.0:12345 gba-signer.gba

# in another shell, run the host-side e2e test
python3 pc/test_e2e.py 0xYOUR_EXPECTED_ADDRESS 12345
```

## Architecture

```
gba-signer/
├── build.sh                 # build without Make (alternative to Makefile)
├── Makefile                 # build with devkitPro Makefile (preferred)
├── src/
│   ├── main.c               # entry point
│   ├── state.c              # FSM: BOOT → WORDS|PIN → DERIVE → READY → SIGN
│   ├── types.h              # u8/u16/u32 (libgba) + u64/s64
│   ├── ui/
│   │   ├── text.c           # consoleDemoInit + helpers, banner
│   │   ├── input.c          # scanKeys + timestamp tracking (entropy)
│   │   ├── keyboard.c       # A–Z keyboard + BIP39 prefix filter
│   │   ├── pin.c            # 4–8 digit PIN via D-pad
│   │   ├── progress.c       # PBKDF2 bar
│   │   ├── chains.c         # chain selector (L/R), chain registry
│   │   ├── splash.c         # boot logo
│   │   └── confirm.c        # tx/sig/connect approval screens
│   ├── crypto/
│   │   ├── crypto.h         # ChaCha20 API + crypto_fill_random
│   │   ├── chacha20.c       # ChaCha20 (RFC 8439) + timer-based RNG
│   │   ├── sha512.c         # SHA-512 (FIPS 180-4)
│   │   ├── hmac_sha512.c    # HMAC-SHA512 (RFC 2104)
│   │   ├── hmac_sha256.c    # HMAC-SHA256 (session MAC)
│   │   ├── pbkdf2.c         # PBKDF2-HMAC-SHA512 (BIP-39 + session unlock)
│   │   ├── keccak256.c      # Keccak-256 (Ethereum, 0x01 padding)
│   │   ├── bip39.c          # mnemonic → seed; checksum; prefix filter
│   │   ├── bip32.c          # m/44'/60'/0'/0/0 + ckd + mod-n add
│   │   ├── ethereum.c       # priv → address + RFC 6979 sig + EIP-55
│   │   ├── rlp.c            # zero-copy RLP decoder (Yellow Paper App. B)
│   │   ├── eth_tx.c         # legacy + EIP-1559 tx decoder + signing hash
│   │   ├── eth_abi.c        # ERC-20/NFT selectors decoder (transfer/approve…)
│   │   ├── uecc_rng.c       # RNG registration for micro-ecc
│   │   └── ../bip39_wordlist.h  # embedded BIP39 wordlist in ROM (16 KB)
│   ├── storage/
│   │   ├── sram.c           # byte-by-byte access to SRAM 0x0E000000
│   │   ├── session.c        # encrypted seed: PBKDF2-HMAC-SHA512 + ChaCha20 + HMAC
│   │   ├── policy.c         # persistent chain lock (which chain is active)
│   │   └── gba_save_type_marker.s  # "SRAM_V113" string for flashcarts
│   └── link/
│       ├── uart.c           # SIO_UART 115200 8N1 + FIFO
│       ├── protocol.c       # handshake + per-opcode framing
│       └── tx_meta.c        # parser of host TLV metadata (origin/symbol/decimals)
├── third_party/
│   ├── micro-ecc/           # secp256k1 + RFC 6979 (kmackay)
│   ├── crypto-algorithms/   # SHA-256 (B-Con) — sha256.c/h only in use
│   ├── libgba/              # libgba (devkitPro)
│   └── bip39-wordlist.txt   # official BIP39 english.txt
├── pc/
│   ├── protocol.py          # opcodes + framing for host-side tools
│   ├── mgba_socket.py       # transport over mGBA -l TCP socket
│   ├── serial_transport.py  # transport over /dev/ttyACM0 (Pico)
│   ├── sig_recover.py       # computes recid (0/1) by trial recovery
│   ├── fake_gba.py          # GBA-side simulator (parses RLP)
│   ├── test_e2e.py          # E2E client with real EIP-1559 tx
│   ├── test_signing_v4.py   # latest protocol coverage harness
│   ├── pi_bridge.py         # legacy UART↔TCP bridge on Raspberry Pi
│   └── metamask_inject.py   # build + sign + broadcast tx (socket or serial)
├── pico/
│   ├── main.py              # MicroPython bridge firmware USB-CDC <-> UART
│   └── uart_debug.py        # one-shot UART probe for hardware bring-up
├── docs/
│   ├── PICO_BRIDGE.md            # wiring + Pico flashing reference
│   └── PICO_BRIDGE_QUICKSTART.md # 5-minute end-user guide
├── extension/                       # browser extension MV3 (WebSerial → Pico → GBA)
│   ├── manifest.json
│   ├── src/
│   │   ├── background/              # service worker + offscreen-bridge glue
│   │   │   ├── service-worker.ts    # MV3 entry + message bus
│   │   │   ├── provider-handler.ts  # thin RPC dispatcher (~90 LOC)
│   │   │   ├── methods/             # split per category (audit-friendly)
│   │   │   │   ├── accounts.ts      # eth_accounts + EIP-2255 permissions
│   │   │   │   ├── chain.ts         # chainId, switchEthereumChain, policy refresh
│   │   │   │   ├── sign.ts          # personal_sign, signTypedData_v4
│   │   │   │   ├── tx.ts            # sendTransaction, signTransaction, meta TLV
│   │   │   │   └── _shared.ts       # cross-method helpers
│   │   │   ├── session.ts           # chrome.storage state (address, RPC overrides)
│   │   │   ├── serial-bridge.ts     # SW → offscreen relay + SW-side lock
│   │   │   ├── rpc-passthrough.ts   # JSON-RPC HTTP fanout with failover
│   │   │   ├── confirm-orchestrator.ts # pending-request state for popup
│   │   │   ├── sig-recover.ts       # recid recovery (v=27/28)
│   │   │   └── protocol.ts          # constants shared with offscreen
│   │   ├── offscreen/               # owner of navigator.serial (not available in SW)
│   │   │   └── serial.ts            # port lifecycle + per-opcode framing + heartbeat
│   │   ├── content/                 # injected into every page (MAIN + ISOLATED)
│   │   │   ├── injected-provider.ts # EIP-1193 + EIP-6963 announce
│   │   │   └── content-script.ts    # postMessage relay → SW
│   │   ├── popup/                   # toolbar icon UI
│   │   ├── confirm/                 # detached "what is being signed" view
│   │   ├── connect/                 # port-pick page (popup loses focus otherwise)
│   │   ├── options/                 # settings page (custom RPCs per chain)
│   │   └── lib/                     # pure data: rlp, eip712, networks, address,
│   │                                #   keccak, hex, selectors, tx_meta, types
│   └── README.md                    # extension install guide
└── tools/
    ├── gen_wordlist.py     # english.txt → src/bip39_wordlist.h
    ├── gbafix.py           # ROM header CRC fix (no devkitPro fallback)
    └── png_to_mode4.py     # boot splash compilation
```

> The `tests/` directory (BIP39 vectors / golden values) is kept
> locally but is not committed to the repo: it contains the standard test
> mnemonic `abandon × 11 + about` and derived addresses; it can be
> regenerated on any machine with `pc/test_e2e.py` and `pc/test_signing_v4.py`.

## Build from source (developers only)

You only need this section if you want to modify the firmware, the
extension, or the Pico bridge. Regular users can skip straight to
[`docs/PICO_BRIDGE_QUICKSTART.md`](docs/PICO_BRIDGE_QUICKSTART.md).

### Toolchain

You need:

- **devkitPro / devkitARM** with libgba ≥ 0.5.4
  - Official path: install `dkp-pacman` and `pacman -S gba-dev`
    (https://devkitpro.org/wiki/Getting_Started). Requires root.
  - User-local path (no root): download tarballs from
    https://github.com/devkitPro/{libgba,devkitarm-rules,devkitarm-crtls}
    and build manually. Compiler binaries (`devkitarm-gcc`,
    `devkitarm-binutils`, `devkitarm-newlib`) ship as `.pkg.tar.zst` packages
    from the community mirror `wii.leseratte10.de` (not official, but same
    content as `pkg.devkitpro.org`).
- **mGBA** (`mgba-qt` for GUI, `mgba` for headless socket).
- **Python 3.10+** with `pip install -r pc/requirements.txt`.

### Build the ROM

There are two paths:

#### With Make (preferred)

```bash
export DEVKITPRO=/opt/devkitpro
export DEVKITARM=$DEVKITPRO/devkitARM
make           # outputs gba-signer.gba
make run       # launches mgba-qt
make socket    # launches mGBA headless with socket :12345
```

#### Without Make (when you cannot install make)

```bash
export DEVKITPRO=/opt/devkitpro
export DEVKITARM=$DEVKITPRO/devkitARM
./build.sh     # equivalent bash script, uses only arm-none-eabi-gcc
```

`build.sh` compiles most `.c` files in Thumb and `pbkdf2.c` +
`uECC.c` in ARM mode, both for `armv4t` (instructions supported by the
GBA’s ARM7TDMI).

### Build the browser extension

```bash
cd extension
npm install
npm run build           # outputs dist/
# load dist/ as "Load unpacked" in chrome://extensions
```

### Build a full release (ROM + Pico bundle + extension ZIP)

```bash
./scripts/build_release.sh        # outputs releases/*.{gba,zip,md}
# uses VERSION=0.1.0 by default; override with: VERSION=0.2.0 ./scripts/build_release.sh
```

This produces all four artifacts ready to upload to a GitHub release:
the `.gba` ROM, the Pico bridge ZIP (main.py + quickstart README),
the extension ZIP (prebuilt `dist/`), and a copy of `RELEASE_NOTES.md`.

## Algorithm verification (no GBA)

```bash
PYTHONPATH=.venv-tools python3 tests/algorithm_verify.py
# → BIP39 seed OK, BIP32 derivation → 0xYOUR_ADDRESS_HERE (== eth_account)
```

This compares the derivation chain against `eth_account.from_mnemonic`,
showing the design is correct before you even load the ROM.

To validate the C code as well (not just the algorithm), see
`tests/host_test.py` — it compiles the `.c` files with native `gcc` + ctypes
and tests them against official vectors from RFC 4231, RFC 8439, BIP39
Trezor, and the official BIP32 spec. Requires `gcc` on the host.

## On-device parsing — why we do not blind-sign hashes

Designs where “the host computes the hash and the GBA only signs” turn the
hardware wallet into a signing oracle: if the bridge is compromised, it can
show `to=charity.eth` on screen while signing `to=attacker.eth`.

Here the flow is:

```
PC  -> Pico bridge -> GBA: unsigned tx RLP bytes
GBA: eth_tx_decode() (legacy or EIP-1559)
GBA: shows chainId, nonce, maxFee, gas, to (EIP-55 checksum), value, data
GBA: user presses A => internal keccak256(rlp_bytes) => ECDSA RFC 6979
GBA -> PC: 65-byte signature (r||s||sentinel)
```

The bridge cannot lie about fields: the GBA shows exactly what it will sign
because it computes the hash itself. The `to` address uses mixed EIP-55
casing to reduce transcription mistakes.

## UART protocol (v6)

Same over mGBA TCP socket or Pico USB-CDC. The GBA continuously pulses
`0xAA` (`READY`) every ~0.5 s while in the awaiting-tx loop. Every host
operation starts with `ACK` and a 1-byte opcode.

```
GBA  → PC : 0xAA  READY        (pulsed every ~0.5 s while idle)
PC   → GBA: 0xBB  ACK
PC   → GBA: <opcode>           (1 byte)
PC   → GBA: <payload …>        (opcode-specific)
GBA processes (may show confirm screen, wait for A/B)
GBA  → PC : <marker> + <payload …>
GBA  → PC : 0xCC  DONE         (closes the exchange)
```

Opcodes (`src/link/protocol.h`):

| Opcode | Direction | Purpose |
|---|---|---|
| `0xC0` `GET_ADDRESS`      | PC → GBA | Read the active EIP-55 address (no signing) |
| `0xC2` `GET_POLICY`       | PC → GBA | Read the chain lock chainId currently set on the cartridge |
| `0xC4` `HEARTBEAT`        | PC → GBA | Update `link:` indicator (5 s tick from the extension) |
| `0xC5` `CONNECT_REQUEST`  | PC → GBA | dApp wants `eth_accounts` access; GBA shows origin + A/B prompt |
| `0xCD` `TX_RLP`           | PC → GBA | Sign an EIP-1559 / legacy tx (length-prefixed RLP payload) |
| `0xD2` `TX_RLP_META`      | PC → GBA | Same as `TX_RLP` + trailing TLV with origin / token symbol / decimals |
| `0xD0` `PERSONAL_SIGN`    | PC → GBA | EIP-191 `personal_sign` — message hashed **on-device** with the standard prefix |
| `0xD1` `TYPED_DATA`       | PC → GBA | EIP-712 — hashes pre-computed by the host (blind signing on hashes, plus a pretty-printed text shown on-screen) |
| `0xCF` `TXRESULT`         | PC → GBA | Post-broadcast feedback (`OK + 32 B hash`, `ERR + msg`, or `NO_BROADCAST`) |

Reply markers from the GBA:

| Marker | Meaning |
|---|---|
| `0xC1` `ADDRSTART` + 20 B  | get_address payload |
| `0xC3` `POLICYSTART` + 4 B | get_policy payload (chainId big-endian) |
| `0xC6` `CONNECT_OK`        | dApp connection approved |
| `0xCE` `SIGSTART` + 65 B   | Signature: `r ‖ s ‖ 0xFE` (host computes real `v` via recid recovery) |
| `0xFF` `CANCEL`            | User pressed B / GBA refused (e.g. malformed payload) |
| `0xFD` `REJECT_CHAIN` + 8 B | Wrong chainId for the lock — `expected ‖ got` big-endian |

`v=0xFE` is a sentinel: the host determines the real `recid` (0 or 1)
by trying public-key recovery with each and comparing to the expected
address (`extension/src/background/sig-recover.ts` /
`pc/sig_recover.py`). This avoids reimplementing point recovery
on-device — micro-ecc does not expose it publicly.

Each opcode handler ends with the GBA sending `0xCC` DONE. For
`TX_RLP*`, after the sig the GBA enters a "BROADCASTING…" screen that
ONLY accepts `TXRESULT`; the host must send it within ~30 s.

## Hardware bridge — Pi Pico (recommended)

See [`docs/PICO_BRIDGE.md`](docs/PICO_BRIDGE.md) for wiring and a step-by-step
flashing guide. Summary:

```
GBA pin 2 (SO,  red)    -> Pico GP1 (UART0 RX, header pin 2)
GBA pin 3 (SI,  orange) -> Pico GP0 (UART0 TX, header pin 1)
GBA pin 6 (GND, blue)   -> Pico GND (header pin 3 or 38)
GBA pins 1, 4, 5: leave unconnected
```

The Pico is native 3.3 V CMOS, same level as GBA SIO → no level shifter
needed. It shows up on the PC as `/dev/ttyACM0` after flashing MicroPython
and `pico/main.py`.

```bash
# 1. Flash MicroPython to the Pico (see docs/PICO_BRIDGE.md)
mpremote cp pico/main.py :main.py
mpremote reset

# 2. From the PC, sign via Pico:
PYTHONPATH=.venv-tools:pc python3 pc/metamask_inject.py \
    --rpc https://rpc.sepolia.org \
    --transport serial --serial-port /dev/ttyACM0 \
    --address-from 0xYOUR_ADDRESS \
    --to 0x... --value-wei 1000000000000000
```

### Alternative: full-size Raspberry Pi (legacy)

The bridge on `/dev/ttyS0` of a Pi 3/4/5 still works — `pc/pi_bridge.py`
exposes UART as a TCP socket and `--transport socket` connects. Handy if
you already have a Pi over SSH. For normal use, the Pico is simpler,
cheaper, and faster (see table in `docs/PICO_BRIDGE.md`).

## Security model (summary)

- **The 12 words never touch SRAM or UART**, not even encrypted. They
  live in stack RAM during input → are converted to a 64-byte seed via
  BIP-39 PBKDF2(2048) → the original words are zeroized immediately.
- **What is stored in SRAM** is that 64-byte seed, encrypted with
  ChaCha20 under a key derived from the PIN:
  - `dk = PBKDF2-HMAC-SHA512(PIN, salt_16B, iters=10000)` → 64 B
  - `key_enc, key_mac = dk[0:32], dk[32:64]`
  - `ciphertext = ChaCha20-XOR(key_enc, nonce_12B, seed)`
  - `mac = HMAC-SHA256(key_mac, version ‖ salt ‖ nonce ‖ ciphertext)`
  - SRAM blob = `"GBAW" ‖ ver ‖ salt ‖ nonce ‖ ciphertext ‖ mac ‖ crc32`
    (133 B total).
- **Wrong PIN does NOT decrypt**: the MAC is checked first; failure
  returns "wrong PIN" instead of silently producing a "ghost wallet".
- **3 failed PIN attempts** in a single session → SRAM wipe. Note: an
  attacker who physically extracts the cartridge SRAM can still
  brute-force offline; PBKDF2 with 10 000 iterations is what makes that
  expensive (~3–14 h for a 7-digit PIN on a fast CPU, vs ~1 second with
  the previous SHA-256 KDF). It is **not** equivalent to a secure
  element — see "Known limitations" below.
- **Backward compat**: a one-time migration upgrades the legacy v2 blob
  (single-SHA-256 KDF, no salt) to v3 on the first successful unlock.
  The user pays one extra PBKDF2 round during that unlock and nothing
  afterwards.
- **The private key lives only in RAM** (`g_node.priv`) for the whole
  unlocked session; it is zeroized on power-off and on lock. The
  uECC stack zeroizes its temporaries too.
- **Signing is RFC 6979** (deterministic) → independent of the GBA's
  weak RNG.
- **`crypto_fill_random`** (XOR of GBA hardware timer counters) is only
  used for ChaCha20 nonce, PBKDF2 salt, and the anti-side-channel hint
  to micro-ecc. Not used on the critical secrecy path.

### Known limitations

- **PIN entry is visible on screen** while typing (shows the current
  digit for confirmation). A shoulder-surfer can read it. The screen
  has no privacy filter — keep the GBA hidden during unlock.
- **EIP-712 (typed data) is blind-signed by the GBA**. The host
  pre-computes `domainSeparator` and `messageHash`; the GBA shows a
  pretty-printed text alongside but does not verify it matches those
  hashes. A compromised browser/Pico bridge could lie about the human
  text. Today the cartridge displays the full hashes for manual
  comparison — but the only practical defence is trusting your host
  install. A real on-device EIP-712 parser is on the roadmap.
- **No firmware integrity check beyond the gbafix header CRC**
  (17 bytes). A modified cartridge could ship an "export_seed" opcode
  without you noticing. Mitigation: build from source and verify the
  resulting `gba-signer.gba` SHA-256 matches the public release.
- **No secure element** — the GBA's ARM7TDMI has no MMU, no NX bit,
  no ASLR, no stack canaries. A memory-corruption bug in our parsers
  (RLP, ABI, TLV) would let an attacker exfiltrate the seed via ROP.
  Today no such bug is known; bounds-checking is consistent throughout
  the receive paths.

### Reporting a vulnerability

If you find a security issue, please **do not open a public issue**.
See [SECURITY.md](SECURITY.md) for the disclosure process.

## Browser extension (real dApps)

`extension/` contains a Chromium-based extension (Manifest V3) that
advertises via EIP-6963 as wallet "GBA Signer" and routes
`eth_sendTransaction`, `personal_sign`, and `eth_signTypedData_v4` to
the GBA using WebSerial → Pico. It coexists with other browser wallets
in the dApp wallet picker.

For end users: download the prebuilt ZIP from the
[latest release](../../releases/latest) and load it via
`chrome://extensions/` → Developer mode → **Load unpacked**.

For developers building it from source: see
[Build the browser extension](#build-the-browser-extension) above and
[`extension/README.md`](extension/README.md) for the full architecture.

## Future roadmap

Done:

- ~~EIP-1559 + on-device RLP parser~~ — all tx fields visible on screen,
  internal hash on GBA.
- ~~EIP-55 checksum casing on screen.~~
- ~~RP2040 (Pi Pico) as USB-CDC bridge~~ — see `pico/`.
- ~~EIP-712 (typed data) for `permit`, Uniswap, OpenSea~~ — `PROTO_TYPED_DATA`
  with pre-computed hashes plus pretty-printed text shown on the GBA.
- ~~EIP-191 (`personal_sign`) for SIWE~~ — `PROTO_PERSONAL_SIGN`.
- ~~Browser extension EIP-1193 + EIP-6963 with WebSerial~~ — see `extension/`.
- ~~ERC-20 / NFT ABI decoder~~ — `transfer`, `approve`, `transferFrom`,
  `safeTransferFrom`, `setApprovalForAll`, WETH `deposit/withdraw`
  show human-readable summary on-screen with INFINITE-approval warnings.
- ~~Chain lock on cartridge~~ — GBA refuses to sign tx for a chainId
  other than the one currently selected with L/R; UI shows clear
  rejection with the expected and got chainIds.
- ~~Host-supplied metadata TLV~~ — origin (anti-phishing), token symbol,
  decimals, contract name forwarded to the GBA without hard-coding any
  contract addresses in ROM.
- ~~EIP-2255 `wallet_requestPermissions` / `wallet_getPermissions`~~ —
  full Uniswap login flow works.
- ~~Per-chain custom RPC overrides (settings page in extension)~~.
- ~~PBKDF2 password stretching for the PIN~~ — v3 blob with 16 B salt
  and 10 000 iters.
- ~~Connect-approval flow on cartridge~~ — first request from each dApp
  shows the origin on the GBA and asks A/B; the decision is cached.
- ~~Link indicator (`OK / idle / OFFLINE`) with 5 s host heartbeat~~ —
  unplug detected in ≤ 10 s.

Pending:

- **Native EIP-712 parser on GBA** — today the cartridge blind-signs
  hashes; a parser would close the largest remaining vector for a
  compromised host.
- **Real-hardware tx on mainnet (Ethereum)** — only tested on Polygon
  and Sepolia so far.
- **Signed firmware** — show a hash of the ROM at boot for visual
  comparison with a public release.
- **Multi-account** — screen to pick derivation index (`m/44'/60'/0'/0/N`).
- **PIN persistent attempt counter** — currently 3 failures *per
  session* wipes SRAM; should be 3 *real* failures stored across boots.
- **Optional BIP-39 passphrase** (25th word).
- **Argon2id KDF** — strictly better than PBKDF2 against ASIC attackers,
  but expensive on ARM7TDMI; not a priority while PBKDF2-10k is in place.
- **Native point recovery (~1 KB ROM)** — so the GBA writes the real
  `v` directly instead of the `0xFE` sentinel.
- **EIP-2930 (access list type 1)** — if it becomes common.
- **Package the extension for the Chrome Web Store** — review + dev
  account.

## References

- BIP39: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
- BIP32: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
- RFC 6979 (deterministic ECDSA):
  https://datatracker.ietf.org/doc/html/rfc6979
- RFC 8439 (ChaCha20-Poly1305):
  https://datatracker.ietf.org/doc/html/rfc8439
- micro-ecc: https://github.com/kmackay/micro-ecc
- libgba (devkitPro): https://github.com/devkitPro/libgba
- gba-link-connection (LinkUART reference):
  https://github.com/rodri042/gba-link-connection
