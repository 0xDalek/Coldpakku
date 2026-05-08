#!/usr/bin/env bash
# Alternativa a `make` para entornos sin Make instalado. Compila la ROM
# usando solo arm-none-eabi-gcc + objcopy + gbafix.
#
# Uso:
#   export DEVKITPRO=/path/to/devkitpro
#   export DEVKITARM=$DEVKITPRO/devkitARM
#   ./build.sh

set -euo pipefail

: "${DEVKITPRO:?DEVKITPRO no definido}"
: "${DEVKITARM:?DEVKITARM no definido}"

PATH="$DEVKITARM/bin:$PATH"

ROOT="$(cd "$(dirname "$0")" && pwd)"
BUILD="$ROOT/build"
TARGET="gba-signer"
mkdir -p "$BUILD"

LIBGBA="$DEVKITPRO/libgba"

CC=arm-none-eabi-gcc
OBJCOPY=arm-none-eabi-objcopy

ARCH_THUMB="-mthumb -mthumb-interwork -march=armv4t -mtune=arm7tdmi"
ARCH_ARM="-marm -mthumb-interwork -march=armv4t -mtune=arm7tdmi"
ARCH="$ARCH_THUMB"

CFLAGS_BASE=(
    -g -Wall -Wextra -O2 -std=gnu99
    -fomit-frame-pointer -ffast-math
    -I "$ROOT/src"
    -I "$ROOT/src/ui"
    -I "$ROOT/src/crypto"
    -I "$ROOT/src/storage"
    -I "$ROOT/src/link"
    -I "$ROOT/third_party/micro-ecc"
    -I "$ROOT/third_party/crypto-algorithms"
    -I "$LIBGBA/include"
    -DuECC_PLATFORM=0
    -DuECC_OPTIMIZATION_LEVEL=2
    -DuECC_SUPPORTS_secp160r1=0
    -DuECC_SUPPORTS_secp192r1=0
    -DuECC_SUPPORTS_secp224r1=0
    -DuECC_SUPPORTS_secp256r1=0
    -DuECC_SUPPORTS_secp256k1=1
    -DuECC_SUPPORT_COMPRESSED_POINT=1
)

CFLAGS_THUMB=("${CFLAGS_BASE[@]}" $ARCH_THUMB)
CFLAGS_ARM=("${CFLAGS_BASE[@]}" $ARCH_ARM)

ASFLAGS=(-g $ARCH_THUMB)

LDFLAGS=(
    -g $ARCH_THUMB
    -specs=gba.specs
    -L "$LIBGBA/lib"
    -Wl,-Map,"$BUILD/$TARGET.map"
)

LIBS=(-lgba)

# Sources compiladas en Thumb (modo por defecto)
SOURCES_C=(
    src/main.c
    src/state.c
    src/ui/text.c
    src/ui/input.c
    src/ui/keyboard.c
    src/ui/pin.c
    src/ui/progress.c
    src/ui/confirm.c
    src/crypto/sha512.c
    src/crypto/hmac_sha512.c
    src/crypto/hmac_sha256.c
    src/crypto/keccak256.c
    src/crypto/bip39.c
    src/crypto/bip32.c
    src/crypto/ethereum.c
    src/crypto/rlp.c
    src/crypto/eth_tx.c
    src/crypto/uecc_rng.c
    src/crypto/chacha20.c
    src/storage/sram.c
    src/storage/session.c
    src/link/uart.c
    src/link/protocol.c
    third_party/crypto-algorithms/sha256.c
)

# Sources compiladas en ARM mode (más rápidas o con asm ARM-only)
SOURCES_C_ARM=(
    src/crypto/pbkdf2.c
    third_party/micro-ecc/uECC.c
)

SOURCES_S=(
    src/storage/gba_save_type_marker.s
)

OBJS=()

for src in "${SOURCES_C[@]}"; do
    obj="$BUILD/$(echo "$src" | tr '/' '_').o"
    echo "  cc  $src"
    "$CC" "${CFLAGS_THUMB[@]}" -c "$ROOT/$src" -o "$obj"
    OBJS+=("$obj")
done

for src in "${SOURCES_C_ARM[@]}"; do
    obj="$BUILD/$(echo "$src" | tr '/' '_').o"
    echo "  cc  [arm] $src"
    "$CC" "${CFLAGS_ARM[@]}" -c "$ROOT/$src" -o "$obj"
    OBJS+=("$obj")
done

for src in "${SOURCES_S[@]}"; do
    obj="$BUILD/$(echo "$src" | tr '/' '_').o"
    echo "  as  $src"
    "$CC" "${ASFLAGS[@]}" -c "$ROOT/$src" -o "$obj"
    OBJS+=("$obj")
done

echo "  ld  $TARGET.elf"
"$CC" "${LDFLAGS[@]}" "${OBJS[@]}" "${LIBS[@]}" -o "$BUILD/$TARGET.elf"

echo "  objcopy $TARGET.gba"
"$OBJCOPY" -O binary "$BUILD/$TARGET.elf" "$ROOT/$TARGET.gba"

if command -v gbafix >/dev/null 2>&1; then
    gbafix "$ROOT/$TARGET.gba" -tGBA_SIGNER -cGSIE -m00
elif [ -f "$ROOT/tools/gbafix.py" ]; then
    # Fallback: implementación pura Python (evita que la ROM se quede en la
    # pantalla del logo de Nintendo en hardware real cuando devkitPro no
    # incluye la herramienta `gbafix` en el PATH).
    echo "  gbafix.py (devkitPro gbafix no encontrado, usando fallback python)"
    python3 "$ROOT/tools/gbafix.py" "$ROOT/$TARGET.gba" -t GBA_SIGNER -c GSIE -m 00
else
    echo "WARNING: gbafix no disponible. La ROM no arrancará en hardware real."
fi

ls -la "$ROOT/$TARGET.gba"
