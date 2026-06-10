# UART protocol (v7)

The same wire protocol runs over the mGBA TCP socket and the Pico USB-CDC
bridge. The GBA continuously pulses `0xAA` (`READY`) every ~0.5 s while in
the awaiting-tx loop. Every host operation starts with `ACK` and a 1-byte
opcode.

```
GBA  → PC : 0xAA  READY        (pulsed every ~0.5 s while idle)
PC   → GBA: 0xBB  ACK
PC   → GBA: <opcode>           (1 byte)
PC   → GBA: <payload …>        (opcode-specific)
GBA processes (may show confirm screen, wait for A/B)
GBA  → PC : <marker> + <payload …>
GBA  → PC : 0xCC  DONE         (closes the exchange)
```

## Opcodes

Defined in `src/link/protocol.h`:

| Opcode | Direction | Purpose |
|---|---|---|
| `0xC0` `GET_ADDRESS`      | PC → GBA | Read the active EIP-55 address (no signing) |
| `0xC2` `GET_POLICY`       | PC → GBA | Read the chain lock chainId currently set on the cartridge |
| `0xC4` `HEARTBEAT`        | PC → GBA | Update `link:` indicator (5 s tick from the extension) |
| `0xC5` `CONNECT_REQUEST`  | PC → GBA | dApp wants `eth_accounts` access; GBA shows origin + A/B prompt |
| `0xCD` `TX_RLP`           | PC → GBA | Sign an EIP-1559 / legacy tx (length-prefixed RLP payload) |
| `0xD2` `TX_RLP_META`      | PC → GBA | Same as `TX_RLP` + trailing TLV with origin / token symbol / decimals |
| `0xD0` `PERSONAL_SIGN`    | PC → GBA | EIP-191 `personal_sign` — message hashed **on-device** with the standard prefix |
| `0xD1` `TYPED_DATA`       | PC → GBA | EIP-712 — host sends pre-computed `domainSeparator` + `messageHash` + pretty text + (v7) optional TLV tree. With the tree present, the user can press **L+R** on the confirm screen to parse the typed data on-device, re-derive the hashes, and verify against the host's. |
| `0xCF` `TXRESULT`         | PC → GBA | Post-broadcast feedback (`OK + 32 B hash`, `ERR + msg`, or `NO_BROADCAST`) |

## Reply markers (GBA → PC)

| Marker | Meaning |
|---|---|
| `0xC1` `ADDRSTART` + 20 B  | get_address payload |
| `0xC3` `POLICYSTART` + 4 B | get_policy payload (chainId big-endian) |
| `0xC6` `CONNECT_OK`        | dApp connection approved |
| `0xCE` `SIGSTART` + 65 B   | Signature: `r ‖ s ‖ 0xFE` (host computes real `v` via recid recovery) |
| `0xFF` `CANCEL`            | User pressed B / GBA refused (e.g. malformed payload) |
| `0xFD` `REJECT_CHAIN` + 8 B | Wrong chainId for the lock — `expected ‖ got` big-endian |

## `TYPED_DATA` payload (v7)

After the 1-byte opcode:

```
+----------------------------+-------+
| domainSeparator            |  32 B |
| messageHash                |  32 B |
| text_len (BE)              |   4 B |
| pretty_text (UTF-8)        |   N B |    1 .. PROTO_TYPED_TEXT_MAX (4096)
| tree_len (BE)              |   2 B |    0 means no tree (legacy v6 mode)
| tlv_tree                   |   M B |    0 .. PROTO_TYPED_TREE_MAX (8192)
+----------------------------+-------+
```

When `tree_len == 0`, behaviour is identical to v6: the GBA hashes
`keccak256(0x19 ‖ 0x01 ‖ ds ‖ mh)`, shows the host's pretty text plus the
truncated hashes, and asks A/B.

When `tree_len > 0` and the parser succeeds, the cartridge **defaults
to parsed view** on the confirm screen: `[TYPED DATA OK][PARSE]` with
the primary type, chain-id, a `hash MATCH` banner, and every
`Domain`/message field flat-indented. Holding **L+R** toggles to the
legacy blind view (text + truncated hex hashes) for users who want to
eyeball the raw values. If the parser detects a hash mismatch the
screen turns into a hard **HOST HASH MISMATCH** warning and the user
can only cancel. If the parser fails (e.g. unsupported array, malformed
TLV) the cartridge silently falls back to the legacy blind view as if
`tree_len == 0` had been sent.

### TLV tree layout

All inline length prefixes are 1 byte; multi-byte integers are
big-endian. The parser caps are defined in `src/crypto/eip712.h`.

```
1B  num_types                 (1 .. EIP712_MAX_TYPES)
repeat num_types:
  1B  name_len                (1 .. EIP712_MAX_NAME_LEN)
  Nb  name                    (ASCII; convention: index 0 is "EIP712Domain")
  1B  num_fields              (1 .. EIP712_MAX_FIELDS_PER_TYPE)
  repeat num_fields:
    1B  fname_len             (1 .. EIP712_MAX_NAME_LEN)
    Nb  fname                 (ASCII)
    1B  ftype_len             (1 .. EIP712_MAX_TYPE_LEN)
    Nb  ftype                 (ASCII type string, see below)
1B  primary_type_index        (0 .. num_types-1)
N B domain_values             (flat, follows types[0])
N B message_values            (flat, follows types[primary_type_index])
```

### Field type strings and value encoding

| Type                   | Encoding                                       |
|------------------------|------------------------------------------------|
| `uintN` / `intN` (N=8..256, multiple of 8) | `N/8` bytes big-endian        |
| `address`              | 20 bytes raw                                   |
| `bool`                 | 1 byte (`0` or `1`)                            |
| `bytesN` (N=1..32)     | `N` bytes raw                                  |
| `string`               | 4 B BE length + UTF-8 bytes                    |
| `bytes`                | 4 B BE length + raw bytes                      |
| `<StructName>`         | Recursive: its fields in declaration order     |
| `<StructName>[]` / `[N]` | 4 B BE count + `count` items (v0.2: flagged as `UNSUPPORTED`; the parser still consumes the bytes so the host can keep going to legacy blind signing if it chose to lie about array support) |

### Why send the tree at all if the GBA can recompute the hashes?

Because the parser is opt-in. The user controls when it runs (L+R), and
it can be skipped if the parser does not yet support the field types in
play (e.g. OpenSea Seaport arrays today). The host always provides the
fallback (pre-computed hashes + pretty text); the parsed view turns the
pretty text from "trust me, this is what those hashes mean" into "the
cartridge verified it". That last bit closes the largest residual
attack surface against a compromised browser extension or USB host.

## `TX_RLP` / `TX_RLP_META` calldata decoding (v0.3, no wire change)

The cartridge decodes the calldata bytes of `TX_RLP` and `TX_RLP_META`
on-device against a hardcoded selector table embedded in the ROM
(`src/crypto/abi_selectors.c`, ~25 entries: ERC-20, ERC-721, WETH,
ERC-2612 Permit, Uniswap V2 router, multicall, Universal Router top
level). When the first 4 bytes of `data` match a known selector and the
remaining args use only the atomic ABI subset (`address`, `bool`,
`uint*`, `int*`, `bytesN`, `bytes`, `string`, `address[]`), the
confirm screen defaults to a parsed view (`function: approve  spender:
0x… amount: MAX (infinite)`) instead of a hex dump. `L+R` toggles to
the legacy hex view. Unknown selectors or arg types fall back
transparently to hex.

Wrappers (`multicall`, Universal Router `execute`) are decoded only at
the top level — the user sees `commands: 3 sub-cmd, inputs: 3 sub-cmd,
deadline: …`, but the inner `bytes` payload is not descended into in
v0.3 (per-protocol sub-decoders are deferred to v0.4).

The wire protocol does NOT change in v0.3: the host still sends the
RLP-encoded unsigned tx exactly as in v0.2, and the GBA does the ABI
decoding from the calldata bytes it already parses out of the RLP.

## Notes

- `v=0xFE` is a sentinel: the host determines the real `recid` (0 or 1) by
  trying public-key recovery with each and comparing to the expected
  address. Implementations: `extension/src/background/sig-recover.ts` and
  `pc/sig_recover.py`. This avoids reimplementing point recovery on-device
  — micro-ecc does not expose it publicly.
- Each opcode handler ends with the GBA sending `0xCC` `DONE`.
- For `TX_RLP*`, after the signature the GBA enters a "BROADCASTING…"
  screen that ONLY accepts `TXRESULT`; the host must send it within ~30 s.

## Reference implementations

Two transports speak this protocol today:

- `pc/mgba_socket.py` — TCP socket over `mgba -l` (no hardware needed).
- `pc/serial_transport.py` — `/dev/ttyACM0` (Pico USB-CDC).

The browser extension speaks it in TypeScript:
`extension/src/offscreen/serial.ts`.

You can use any of these as templates if you want to write a fourth client.
