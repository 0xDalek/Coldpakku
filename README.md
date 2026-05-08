# GBA Signer — hardware wallet Ethereum sobre Game Boy Advance

Usa una Game Boy Advance como dispositivo físico de firma de transacciones
Ethereum. Las 12 palabras BIP39 nunca salen de la GBA y la clave privada
nunca abandona la RAM del cartucho. **La GBA parsea la transacción ella
misma**: el bridge no puede mostrarte un `to` bonito en pantalla y firmar
otro hash.

> Estado actual: **núcleo completo + parser RLP on-device**. La ROM compila
> a un binario de ~150 KB, el algoritmo BIP39→PBKDF2→BIP32 produce la misma
> dirección que `eth_account` (test reproducible en
> `tests/algorithm_verify.py`), las transacciones EIP-1559 y legacy se
> decodifican y hashean dentro del GBA (`tests/test_rlp_parity.py`
> demuestra paridad de hash con `eth_account` en 100 txs aleatorias) y el
> handshake UART está validado E2E con un fake GBA en Python. Falta
> únicamente la prueba en hardware real (GBA + Pi Pico + Sepolia).

## Quick start (mGBA)

```bash
# 1. Instalar devkitARM (ver "Toolchain" abajo) y exportar:
export DEVKITPRO=/opt/devkitpro
export DEVKITARM=$DEVKITPRO/devkitARM

# 2. Compilar
./build.sh                 # produce gba-signer.gba en la raíz

# 3. Lanzar mGBA con socket abierto para el lado PC
mgba -l 0.0.0.0:12345 gba-signer.gba

# 4. (en el GBA) introducir las 12 palabras BIP39 y dejarla en READY
# 5. (en otro shell) firmar una tx
python3 pc/test_e2e.py 0xTU_DIRECCION_ESPERADA 12345
```

## Arquitectura

```
gba-signer/
├── build.sh                 # build sin Make (alternativa al Makefile)
├── Makefile                 # build con devkitPro Makefile (preferido)
├── src/
│   ├── main.c               # entry point
│   ├── state.c              # FSM: BOOT → WORDS|PIN → DERIVE → READY → SIGN
│   ├── types.h              # u8/u16/u32 (libgba) + u64/s64
│   ├── ui/
│   │   ├── text.c           # consoleDemoInit + helpers
│   │   ├── input.c          # scanKeys + tracking de timestamps (entropía)
│   │   ├── keyboard.c       # teclado A-Z + filtro prefijo BIP39
│   │   ├── pin.c            # PIN 4-8 dígitos vía D-pad
│   │   ├── progress.c       # barra PBKDF2
│   │   └── confirm.c        # destino + valor + A/B
│   ├── crypto/
│   │   ├── crypto.h         # API ChaCha20 + crypto_fill_random
│   │   ├── chacha20.c       # ChaCha20 (RFC 8439) + RNG basado en timers
│   │   ├── sha512.c         # SHA-512 (FIPS 180-4)
│   │   ├── hmac_sha512.c    # HMAC-SHA512 (RFC 2104)
│   │   ├── pbkdf2.c         # PBKDF2-HMAC-SHA512 (RFC 8018), compilado en ARM/IWRAM
│   │   ├── keccak256.c      # Keccak-256 (Ethereum, padding 0x01)
│   │   ├── bip39.c          # mnemonic → seed; checksum; filtro prefix
│   │   ├── bip32.c          # m/44'/60'/0'/0/0 + ckd + suma mod n
│   │   ├── ethereum.c       # priv → address + firma RFC 6979 + EIP-55
│   │   ├── rlp.c            # RLP decoder zero-copy (Yellow Paper App. B)
│   │   ├── eth_tx.c         # decoder tx legacy + EIP-1559 + signing hash
│   │   ├── uecc_rng.c       # registro de RNG en micro-ecc
│   │   └── ../bip39_wordlist.h  # wordlist BIP39 embebida en ROM (16 KB)
│   ├── storage/
│   │   ├── sram.c           # acceso byte-a-byte a SRAM 0x0E000000
│   │   ├── session.c        # struct cifrado en SRAM + CRC32
│   │   └── gba_save_type_marker.s  # cadena "SRAM_V113" para flashcarts
│   └── link/
│       ├── uart.c           # SIO_UART 115200 8N1 + FIFO
│       └── protocol.c       # FSM handshake AA/BB → payload → 65B sig → CC
├── third_party/
│   ├── micro-ecc/           # secp256k1 + RFC 6979 (kmackay)
│   ├── crypto-algorithms/   # SHA-256 (B-Con) — solo sha256.c/h en uso
│   ├── libgba/              # libgba (devkitPro)
│   └── bip39-wordlist.txt   # english.txt oficial BIP39
├── pc/
│   ├── protocol.py          # opcode 0xCD TX_RLP + handshake nuevo
│   ├── mgba_socket.py       # transport sobre socket TCP de mGBA -l
│   ├── serial_transport.py  # transport sobre /dev/ttyACM0 (Pico)
│   ├── sig_recover.py       # calcula recid (0/1) probando recover
│   ├── fake_gba.py          # simulador del lado GBA (parsea RLP)
│   ├── test_e2e.py          # cliente E2E con tx EIP-1559 real
│   ├── pi_bridge.py         # legacy bridge UART↔TCP en Raspberry Pi
│   └── metamask_inject.py   # construye + firma + broadcast tx (socket o serial)
├── pico/
│   └── main.py              # firmware MicroPython del bridge USB-CDC <-> UART
├── docs/
│   └── PICO_BRIDGE.md       # guía de cableado y flasheo del Pico
├── tests/
│   ├── algorithm_verify.py  # valida BIP39/BIP32/address contra eth_account
│   ├── test_rlp_parity.py   # 100 txs aleatorias: keccak(rlp) == eth_account hash
│   ├── host_test.py         # compila los .c con gcc y los ejecuta vs vectores oficiales
│   └── golden_values.json   # snapshot de valores esperados
└── tools/
    └── gen_wordlist.py      # english.txt → src/bip39_wordlist.h
```

## Toolchain

Necesitas:

- **devkitPro / devkitARM** con libgba ≥ 0.5.4
  - Forma oficial: instalar `dkp-pacman` y `pacman -S gba-dev`
    (https://devkitpro.org/wiki/Getting_Started). Requiere root.
  - Forma user-local (sin root): bajar tarballs de
    https://github.com/devkitPro/{libgba,devkitarm-rules,devkitarm-crtls}
    y compilar manualmente. Las binarias del compilador (`devkitarm-gcc`,
    `devkitarm-binutils`, `devkitarm-newlib`) se distribuyen como paquetes
    `.pkg.tar.zst` desde el mirror comunitario `wii.leseratte10.de` (no es
    oficial, pero es el mismo contenido que distribuye `pkg.devkitpro.org`).
- **mGBA** (`mgba-qt` para GUI, `mgba` para socket headless).
- **Python 3.10+** con `pip install -r pc/requirements.txt`.

## Build

Hay dos rutas:

### Con Make (preferida)

```bash
export DEVKITPRO=/opt/devkitpro
export DEVKITARM=$DEVKITPRO/devkitARM
make           # produce gba-signer.gba
make run       # lanza mgba-qt
make socket    # lanza mgba en modo headless con socket :12345
```

### Sin Make (cuando no se puede instalar make)

```bash
export DEVKITPRO=/opt/devkitpro
export DEVKITARM=$DEVKITPRO/devkitARM
./build.sh     # script bash equivalente, usa solo arm-none-eabi-gcc
```

`build.sh` compila la mayoría de los `.c` en Thumb y `pbkdf2.c` +
`uECC.c` en ARM mode, ambos para `armv4t` (instrucciones soportadas por el
ARM7TDMI del GBA).

## Verificación de algoritmos (sin GBA)

```bash
PYTHONPATH=.venv-tools python3 tests/algorithm_verify.py
# → BIP39 seed OK, BIP32 derivación → 0xYOUR_ADDRESS_HERE (== eth_account)
```

Esto compara la cadena de derivación contra `eth_account.from_mnemonic`,
demostrando que el diseño es correcto antes incluso de cargar la ROM.

Para validar también el código C (no solo el algoritmo) hay
`tests/host_test.py` — compila los `.c` con `gcc` nativo + ctypes y los
prueba contra vectores oficiales de RFC 4231, RFC 8439, BIP39 trezor y
BIP32 oficial. Requiere `gcc` instalado en el host.

## Parsing on-device — por qué no firmamos hashes ciegos

Diseños tipo "el host computa el hash y el GBA solo firma" convierten al
hardware wallet en un signing oracle: si el bridge se compromete, te puede
mostrar `to=charity.eth` por la pantalla mientras firma `to=attacker.eth`.

Aquí el flujo es:

```
PC  -> Pico bridge -> GBA: bytes RLP de la tx unsigned
GBA: eth_tx_decode() (legacy o EIP-1559)
GBA: muestra chainId, nonce, maxFee, gas, to (EIP-55 checksum), value, data
GBA: usuario pulsa A => keccak256(rlp_bytes) interno => ECDSA RFC 6979
GBA -> PC: firma 65B (r||s||sentinel)
```

El bridge no puede mentir sobre los campos: la GBA muestra exactamente lo
que va a firmar porque ella es la que computa el hash. La address `to` se
muestra con casing EIP-55 mixto para evitar confusiones de transcripción.

## Protocolo UART (v2 — RLP)

Idéntico tanto sobre socket TCP de mGBA como sobre USB-CDC del Pico.

```
GBA  → PC : 0xAA           (READY)
PC   → GBA: 0xBB           (ACK)
PC   → GBA: 0xCD           (TX_RLP opcode)
PC   → GBA: 4B len_be + N bytes RLP serializados (N <= 4096)
GBA decodifica, muestra todos los campos parseados, usuario A/B
GBA  → PC : 65B firma (r||s||v=0xFE)  ó  0xFF (CANCEL)
GBA  → PC : 0xCC           (DONE)
```

Para EIP-1559 los `N bytes` empiezan con `0x02 || rlp([chainId, nonce,
maxPriorityFeePerGas, maxFeePerGas, gas, to, value, data, accessList])`.
Para legacy son `rlp([nonce, gasPrice, gas, to, value, data, chainId, 0,
0])`. La GBA admite cualquiera, deduce el tipo del primer byte.

`v=0xFE` es un sentinel: el lado PC determina el `recid` real (0 o 1)
probando recuperar la pubkey con cada uno y comparándola con la address
esperada (`pc/sig_recover.py`). Esto evita reimplementar point recovery
on-device — micro-ecc no lo expone públicamente.

## Hardware bridge — Pi Pico (recomendado)

Ver [`docs/PICO_BRIDGE.md`](docs/PICO_BRIDGE.md) para el cableado y la
guía de flasheo paso a paso. Resumen:

```
GBA pin 2 (SO,  rojo)    -> Pico GP1 (UART0 RX, header pin 2)
GBA pin 3 (SI,  naranja) -> Pico GP0 (UART0 TX, header pin 1)
GBA pin 6 (GND, azul)    -> Pico GND (header pin 3 o 38)
GBA pins 1, 4, 5: sin conectar
```

El Pico es 3.3V CMOS nativo, mismo nivel que el SIO del GBA → no hace falta
level shifter. Aparece en el PC como `/dev/ttyACM0` después de flashear
MicroPython y `pico/main.py`.

```bash
# 1. flashea MicroPython al Pico (ver docs/PICO_BRIDGE.md)
mpremote cp pico/main.py :main.py
mpremote reset

# 2. desde el PC, firmar via Pico:
PYTHONPATH=.venv-tools:pc python3 pc/metamask_inject.py \
    --rpc https://rpc.sepolia.org \
    --transport serial --serial-port /dev/ttyACM0 \
    --address-from 0xTU_DIRECCION \
    --to 0x... --value-wei 1000000000000000
```

### Alternativa: Raspberry Pi grande (legacy)

El bridge sobre `/dev/ttyS0` de un Pi 3/4/5 sigue funcionando — `pc/pi_bridge.py`
expone la UART como TCP socket y `--transport socket` se conecta. Útil si
ya tienes un Pi conectado por SSH. Pero para uso normal, el Pico es más
simple, más barato y más rápido (ver tabla en `docs/PICO_BRIDGE.md`).

## Modelo de seguridad (resumen)

- Las 12 palabras nunca tocan SRAM ni UART, ni siquiera cifradas.
- Lo que se guarda en SRAM es la **seed derivada** (64 bytes), cifrada
  con ChaCha20 usando `key = SHA-256(PIN)`.
- 3 intentos de PIN fallidos → wipe SRAM.
- La clave privada vive solo en RAM; se zeroiza al apagar/lock.
- Firma RFC 6979 (determinista) → independiente del RNG débil del GBA.
- `crypto_fill_random` solo se usa para nonces de ChaCha20 (no en el
  camino crítico de confidencialidad de la seed siempre que el PIN tenga
  suficiente entropía).

## Roadmap futuro

- Implementar point recovery propia (~1 KB) para que el GBA escriba el
  `v` real en lugar del sentinel.
- ~~EIP-1559 + parser RLP on-device~~ (hecho — todos los campos visibles
  en pantalla y hash interno).
- ~~EIP-55 checksum casing en pantalla~~ (hecho).
- ~~RP2040 (Pi Pico) como bridge USB-CDC~~ (hecho — ver `pico/`).
- EIP-712 (typed data) para firmar `permit`, login dApps, OpenSea.
- EIP-2930 (access list type 1) si llega a ser común.
- Multi-cuenta: pantalla para elegir índice de derivación
  (`m/44'/60'/0'/0/N`).
- Hardening de PIN: contador persistente en SRAM con wipe a 3 fallos
  reales (no solo a 3 fallos por sesión).
- BIP39 passphrase opcional (25th word).
- MetaMask Snap que dirija las firmas hacia el endpoint del Pico/Pi.

## Referencias

- BIP39: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
- BIP32: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
- RFC 6979 (ECDSA determinista):
  https://datatracker.ietf.org/doc/html/rfc6979
- RFC 8439 (ChaCha20-Poly1305):
  https://datatracker.ietf.org/doc/html/rfc8439
- micro-ecc: https://github.com/kmackay/micro-ecc
- libgba (devkitPro): https://github.com/devkitPro/libgba
- gba-link-connection (referencia para LinkUART):
  https://github.com/rodri042/gba-link-connection
