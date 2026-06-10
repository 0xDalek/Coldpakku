# Coldpakku — Ethereum hardware wallet on Game Boy Advance

Use a Game Boy Advance as a physical signing device for Ethereum
transactions. The 12 BIP-39 words never leave the cartridge, the
private key never leaves cartridge RAM, and **the GBA parses each
transaction itself** — so the bridge cannot show a tidy `to` on
screen while signing a different hash.

> Status: **end-to-end working on real hardware**. ROM ~205 KB.
> Tested on physical GBA + Pi Pico bridge + Chromium extension:
> - dApp connect/login via EIP-2255 `wallet_requestPermissions` (Uniswap, etc.)
> - `personal_sign` (EIP-191), SIWE-style login
> - `eth_signTypedData_v4` (EIP-712), Permit / Permit2
> - `eth_sendTransaction` on Polygon mainnet (Uniswap swap broadcast end-to-end)
> - Chain lock on cartridge: tx for wrong chainId is rejected on-device
>
> Algorithm parity verified against `eth_account` and a 100-tx random RLP
> parity suite (see [`tests/`](tests/) and [`docs/BUILDING.md`](docs/BUILDING.md)).

## Install (no build tools required)

Three downloadable artifacts (no `npm`, no `make`, no devkitARM) — get
them from the [latest GitHub release](../../releases/latest):

| File | Where it goes |
|---|---|
| `coldpakku-v0.3.0.gba`               | Copy to your flashcart's SD card (EZ-Flash, EverDrive, etc.) |
| `coldpakku-pico-bridge-v0.3.0.zip`   | Unzip and follow [`docs/PICO_BRIDGE_QUICKSTART.md`](docs/PICO_BRIDGE_QUICKSTART.md) (5 min) |
| `coldpakku-extension-v0.3.0.zip`     | Unzip, then `chrome://extensions/` → Developer mode → **Load unpacked** → pick the unzipped folder |

### Hardware checklist

- A Game Boy Advance + flashcart with the ROM
- A Raspberry Pi Pico wired to a GBA link cable
  (3 wires — diagram in [`docs/PICO_BRIDGE.md`](docs/PICO_BRIDGE.md))
- A Chromium-based browser (Chrome, Edge, Brave, Arc — anything with
  WebSerial, MV3 and Chrome ≥ 115)

### First use (one-time setup)

1. Boot the GBA. Type your **12 BIP-39 words** with the on-screen
   keyboard and pick a **PIN** (4–8 digits). Both stay encrypted in
   cartridge SRAM and never leave the GBA. The PIN is stretched with
   PBKDF2-HMAC-SHA512 (10 000 iterations) — first unlock takes ~10 s,
   the bar shows progress. Subsequent boots just ask for the PIN.
2. Plug the Pico via USB.
3. Click the **Coldpakku** extension icon → **Connect GBA** → pick the
   Pico's serial port (it shows up as "USB Serial Device" or
   "Raspberry Pi Pico"). Remembered per browser profile.
4. Visit any dApp (Uniswap, Aave, OpenSea…) and pick **Coldpakku** in
   the wallet picker. The extension advertises itself via EIP-6963
   only — it does **not** override `window.ethereum`, so legacy dApps
   that ignore EIP-6963 (PancakeSwap legacy, OpenSea legacy) will
   not see Coldpakku.
5. On the first request from each dApp, the **GBA shows a "CONNECT
   REQ" screen with the origin** (e.g. `app.uniswap.org`). Press
   **A** to allow, **B** to deny — cached after that.

Every transaction or message asks for confirmation **on the GBA**
(press **A** to sign, **B** to cancel). The browser extension only
shows what is being signed; the actual approval lives on the cartridge.

### Cartridge buttons (AWAITING TX screen)

| Button | Action |
|---|---|
| `L` / `R` (or `LEFT` / `RIGHT` d-pad) | Switch the active chain. Persists in SRAM. |
| `START` | Lock the session: wipes seed + private key from RAM. Requires PIN to come back. Encrypted blob in SRAM preserved. |
| `SELECT` | **Wipe wallet** — destructive confirmation screen. Hold `A` for 3 s (with progress bar) to erase the encrypted seed from SRAM. Any other key cancels. **Back up your 12 BIP-39 words first.** |
| `A` / `B` on a confirm screen | Approve / reject the pending operation. |

### Custom RPCs (optional)

Default networks ship with public RPCs (publicnode, llamarpc, official
endpoints). Open the extension popup → **`settings`** to add your own
RPC URLs per chain (Alchemy, Infura, your own node…). Your URLs are
tried first, with the public ones as fallback. Includes a "Test"
button that runs `eth_blockNumber` and reports latency. Config lives
in `chrome.storage.local` and exports/imports as JSON.

> Privacy note: whatever RPC you choose sees your balance queries and
> broadcasted signed txs. For full privacy run your own node.

### Try it on mGBA (without real hardware)

```bash
./build.sh                                   # see docs/BUILDING.md
mgba -l 0.0.0.0:12345 coldpakku.gba

# in another shell:
python3 pc/test_e2e.py 0xYOUR_EXPECTED_ADDRESS 12345
```

## Architecture

```
src/      firmware (C99 for ARM7TDMI): crypto, ui, storage, link
pc/       host-side tools: socket/serial transports, e2e tests
pico/     MicroPython bridge firmware (USB-CDC ↔ UART)
extension/ Chromium MV3 wallet (WebSerial → Pico → GBA)
tests/    parity tests against eth_account + RFC vectors
docs/     ARCHITECTURE.md · BUILDING.md · PROTOCOL.md · PICO_BRIDGE*.md
```

For the full file tree and module-by-module purpose see
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md). For the UART wire
protocol (opcodes, framing, recid recovery) see
[`docs/PROTOCOL.md`](docs/PROTOCOL.md).

## Build from source

Build the ROM with devkitARM + `make` (or `./build.sh` if you can't
install make). Build the extension with `npm install && npm run
build` in `extension/`. Full instructions, toolchain install (with
and without root), release packaging and the test suite are in
[`docs/BUILDING.md`](docs/BUILDING.md).

## Hardware bridge — Pi Pico

A Raspberry Pi Pico (~€4) flashed with MicroPython acts as the
GBA-to-USB bridge. Native 3.3 V CMOS, same as GBA SIO, so no level
shifter is needed. Wiring + flashing in
[`docs/PICO_BRIDGE.md`](docs/PICO_BRIDGE.md); the 5-minute
end-user version is [`docs/PICO_BRIDGE_QUICKSTART.md`](docs/PICO_BRIDGE_QUICKSTART.md).

A legacy bridge on full-size Raspberry Pi 3/4/5 over `/dev/ttyS0`
also works (`pc/pi_bridge.py` + `--transport socket`) but the Pico is
simpler, cheaper, and faster.

## Security model

- **The 12 words never touch SRAM or UART**, not even encrypted. They
  live in stack RAM during input → BIP-39 PBKDF2(2048) produces a
  64-byte seed → the original words are zeroized immediately.
- **What is stored in SRAM** is that seed, encrypted with ChaCha20
  under a key derived from the PIN:
  - `dk = PBKDF2-HMAC-SHA512(PIN, salt_16B, iters=10000)` → 64 B
  - `key_enc, key_mac = dk[0:32], dk[32:64]`
  - `ct = ChaCha20-XOR(key_enc, nonce_12B, seed)`
  - `mac = HMAC-SHA256(key_mac, version ‖ salt ‖ nonce ‖ ct)`
  - blob = `"GBAW" ‖ ver ‖ salt ‖ nonce ‖ ct ‖ mac ‖ crc32` (133 B)
- **Wrong PIN does NOT decrypt**: MAC is checked first, so failure
  returns "wrong PIN" instead of producing a "ghost wallet".
- **3 failed PIN attempts** in a single session wipe SRAM. A physical
  attacker who extracts the SRAM can still brute-force offline;
  PBKDF2 with 10 000 iterations is what makes that expensive
  (~3–14 h for a 7-digit PIN on a fast CPU).
- **Private key lives only in RAM** (`g_node.priv`) for the unlocked
  session, zeroized on power-off and on lock. micro-ecc zeroes its
  temporaries too.
- **Signing is RFC 6979** (deterministic) — independent of the GBA's
  weak RNG.

EIP-712 typed data is **parsed on-device by default**: the cartridge
re-derives `domainSeparator` and `messageHash` from the host's TLV,
verifies them byte-for-byte, and shows the message fields flat-indented
on the confirm screen. A mismatch hard-blocks the signature. Hold
**L+R** if you want to toggle back to the raw hex view. See
[`docs/PROTOCOL.md`](docs/PROTOCOL.md#typed_data-payload-v7).

`eth_sendTransaction` calldata is **decoded on-device** for ~25 known
selectors (v0.3): ERC-20 (`transfer` / `approve`-with-`MAX` /
`transferFrom` / `mint` / `burn`), ERC-721 / 1155
(`setApprovalForAll`, `safeTransferFrom`), WETH `deposit`/`withdraw`,
ERC-2612 `permit`, Uniswap V2 router (all `swap*`,
`addLiquidity*`, `removeLiquidity*`), `multicall(bytes[])`, and
Universal Router `execute(...)` (top-level: `N sub-cmd` without
descending into the inner payload). Unknown selectors and functions
whose args use tuples or non-`address[]` arrays fall back transparently
to the hex view. Press `R` from the confirm screen to walk into the
parsed page when the cartridge recognises the selector.

For known limitations (PIN visible on screen, EIP-712 arrays still
blind-signed today, calldata for unknown selectors still falls back to
hex, no secure element) and the roadmap to address them, see
[`RELEASE_NOTES.md`](RELEASE_NOTES.md).

### Reporting a vulnerability

If you find a security issue, please **do not open a public issue**.
See [`SECURITY.md`](SECURITY.md) for the disclosure process.

## Donations

Coldpakku is built and maintained in spare time. If it is useful to
you, donations are appreciated and help fund hardware testing on
mainnet (gas alone adds up quickly).

Ethereum / EVM-compatible address — works on Ethereum mainnet,
Polygon, Base, Arbitrum, Optimism, zkSync Era, Linea, Scroll, Blast,
Mantle, Gnosis, BSC, Avalanche, and any other EVM chain:

    0x3E0B74331f0D26745966A4e2695122fa6Dc5C65b

You can also use the **Sponsor** button at the top of the repository
(links to the same address on Etherscan so you can verify it before
sending).

## References

- BIP39 / BIP32: <https://github.com/bitcoin/bips>
- RFC 6979 (deterministic ECDSA): <https://datatracker.ietf.org/doc/html/rfc6979>
- RFC 8439 (ChaCha20): <https://datatracker.ietf.org/doc/html/rfc8439>
- micro-ecc: <https://github.com/kmackay/micro-ecc>
- libgba (devkitPro): <https://github.com/devkitPro/libgba>
- gba-link-connection (LinkUART reference): <https://github.com/rodri042/gba-link-connection>
