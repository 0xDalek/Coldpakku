/*
 * Shim para compilar los módulos crypto en el host (gcc nativo) sin libgba.
 * Sustituye <gba_types.h> con typedefs de stdint.
 *
 * Solo se usa cuando compilamos como librería compartida en tests/host_test.py.
 */
#ifndef GBA_SIGNER_SHIM_HOST_H
#define GBA_SIGNER_SHIM_HOST_H

#include <stdint.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t   s8;
typedef int16_t  s16;
typedef int32_t  s32;
typedef int64_t  s64;

#define _gba_types_h_ 1   /* impide que se incluya el real */

#endif
