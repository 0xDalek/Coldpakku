# Architecture

Repository layout. Each module is small and self-contained; if you want to
understand the cartridge boot path, read `src/main.c` → `src/state.c`.

```
coldpakku/
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
│   │   ├── eth_abi.c        # ERC-20/NFT selectors decoder (transfer/approve…) — legacy ad-hoc
│   │   ├── abi_selectors.c  # 25-entry ABI selector table (v0.3 generic decoder)
│   │   ├── abi_decoder.c    # head/tail ABI decoder over abi_selectors table
│   │   ├── eip712.c         # on-device EIP-712 hashStruct (re-derives the host's hashes)
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
├── tests/
│   ├── algorithm_verify.py  # BIP39/BIP32/ETH derivation parity vs eth_account
│   ├── host_test.py         # compile crypto .c with native gcc + ctypes vs RFC vectors
│   ├── test_rlp_parity.py   # 100 random txs: our RLP hash == eth_account hash
│   ├── test_eth_abi.py      # legacy ABI selector decoder vectors (eth_abi.c)
│   ├── test_abi_decoder.py  # v0.3 generic ABI decoder via gcc + ctypes (vectors vs eth_abi)
│   ├── abi_decoder_oracle.py# Python re-impl of abi_decoder.c (gcc-independent spec check)
│   └── golden_values.json   # snapshot from algorithm_verify (abandon×11 about)
├── docs/
│   ├── ARCHITECTURE.md           # this file
│   ├── BUILDING.md               # devkitARM, Makefile/build.sh, release tooling
│   ├── PROTOCOL.md               # UART opcode reference
│   ├── PICO_BRIDGE.md            # Pi Pico wiring + flashing reference
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

## On-device parsing — why we do not blind-sign hashes

Designs where "the host computes the hash and the GBA only signs" turn the
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

EIP-712 typed data follows the same principle in v0.2: the host always
ships the precomputed `domainSeparator` / `messageHash` **and** a TLV
serialization of the typed data. By default the cartridge decodes the
TLV, recomputes both hashes on-device with `src/crypto/eip712.c`, shows
the message fields parsed (flat-indented, struct-aware up to depth 4),
and refuses to sign on mismatch. `L+R` toggles to the legacy blind view
(text + hex hashes) for users who want to verify the raw bytes. Arrays
and unsupported types make the parser silently fall back to the blind
view — no toggle, host hashes only, with a clear "trust the host"
warning. See the [protocol spec](PROTOCOL.md#typed_data-payload-v7) for
the wire layout.

`eth_sendTransaction` calldata follows the same pattern in v0.3 (without
needing a wire change): the firmware carries a 25-entry table of well
known function selectors in `src/crypto/abi_selectors.c`, and
`src/crypto/abi_decoder.c` walks the ABI head/tail layout to produce a
flat list of `(name, decoded value)` pairs that `src/ui/confirm.c`
renders on the parsed page. Two specialty paths run in parallel:

1. The legacy `eth_abi.c` (v0.1) still drives the dedicated pretty
   pages for `transfer`/`approve`/`transferFrom`/`safeTransferFrom`/
   `setApprovalForAll`/`deposit`/`withdraw` so the v0.2 UX with
   "INFINITE APPROVAL" / "ALL NFTS APPROVED" warnings is untouched.
2. The new generic `abi_decoder.c` (v0.3) takes over for the ~18 new
   selectors the legacy decoder did not cover (Uniswap V2 router fns,
   ERC-2612 permit, multicall, Universal Router execute, …), with a
   common flat-indented rendering. Wrapper functions are decoded
   top-level only: the inner `bytes` / `bytes[]` payload is shown as
   `N sub-cmd` without descending into it, deferring per-protocol
   sub-decoding to a v0.4 plugin system.

If neither decoder recognises the selector, the confirm screen falls
back to the legacy hex view — same behaviour as v0.2 for unknown
calldata. The protocol does not change in v0.3 (still wire v7): the
host sends the same RLP-encoded unsigned tx and the GBA decodes the
calldata it already had to parse anyway to compute the signing hash.
