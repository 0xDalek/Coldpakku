# Building from source

You only need this guide if you want to modify the firmware, the browser
extension, or the Pi Pico bridge. Regular users can grab the prebuilt
artifacts from the [latest GitHub release](../../releases/latest) and
follow [`PICO_BRIDGE_QUICKSTART.md`](PICO_BRIDGE_QUICKSTART.md).

## Toolchain

- **devkitPro / devkitARM** with libgba ≥ 0.5.4
  - Official path: install `dkp-pacman` and `pacman -S gba-dev` (see
    <https://devkitpro.org/wiki/Getting_Started>). Requires root.
  - User-local path (no root): download the tarballs from
    <https://github.com/devkitPro/libgba>,
    <https://github.com/devkitPro/devkitarm-rules>, and
    <https://github.com/devkitPro/devkitarm-crtls>, and build manually.
    Compiler binaries (`devkitarm-gcc`, `devkitarm-binutils`,
    `devkitarm-newlib`) ship as `.pkg.tar.zst` packages from the community
    mirror `wii.leseratte10.de` (not official, but same content as
    `pkg.devkitpro.org`).
- **mGBA** (`mgba-qt` for GUI, `mgba` for headless socket).
- **Python 3.10+** with `pip install -r pc/requirements.txt`.
- **Node 18+** if you want to build the extension.

## Build the ROM

Two paths, pick whichever your environment allows.

### With Make (preferred)

```bash
export DEVKITPRO=/opt/devkitpro
export DEVKITARM=$DEVKITPRO/devkitARM
make           # outputs coldpakku.gba
make run       # launches mgba-qt
make socket    # launches mGBA headless with socket :12345
```

### Without Make (when you cannot install make)

```bash
export DEVKITPRO=/opt/devkitpro
export DEVKITARM=$DEVKITPRO/devkitARM
./build.sh     # equivalent bash script, uses only arm-none-eabi-gcc
```

`build.sh` compiles most `.c` files in Thumb and `pbkdf2.c` + `uECC.c` in
ARM mode, both for `armv4t` (instructions supported by the GBA's
ARM7TDMI).

## Build the browser extension

```bash
cd extension
npm install
npm run build           # outputs dist/
# load dist/ as "Load unpacked" in chrome://extensions
```

## Build a full release (ROM + Pico bundle + extension ZIP)

```bash
./scripts/build_release.sh        # outputs releases/*.{gba,zip,md}
# uses VERSION=0.3.0 by default; override with: VERSION=0.4.0 ./scripts/build_release.sh
```

This produces four artifacts ready to upload to a GitHub release: the
`.gba` ROM, the Pico bridge ZIP (main.py + quickstart README), the
extension ZIP (prebuilt `dist/`), and a copy of `RELEASE_NOTES.md`.

## Run the test suite

All tests use the standard Trezor mnemonic `abandon×11 + about`
(public, no private data) — see
[`../tests/golden_values.json`](../tests/golden_values.json).

Algorithm parity vs reference libraries (no GBA, no devkitARM):

```bash
python3 -m pip install -r pc/requirements.txt
python3 tests/algorithm_verify.py
# → BIP39 seed OK, BIP32 derivation → 0x9858EfFD...EcaEda94 (== eth_account)
```

C code validated against RFC vectors (compiles native with gcc + ctypes):

```bash
python3 tests/host_test.py
# → SHA-512, HMAC-SHA-512, PBKDF2, Keccak-256, BIP32 derivation, ChaCha20,
#   ECDSA RFC 6979 + recover
```

RLP hash parity vs eth_account on 100 random txs:

```bash
python3 tests/test_rlp_parity.py
# → 80 EIP-1559 + 20 legacy txs match byte-for-byte
```

ABI selector decoder vectors (ERC-20 / NFT calls, including malformed):

```bash
python3 tests/test_eth_abi.py
# → transfer / approve / transferFrom / safeTransferFrom / setApprovalForAll
#   + reject short, padding-dirty, bool-out-of-range, unknown selector...
```
