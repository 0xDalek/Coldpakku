/*
 * Shim for building the crypto modules on the host (native gcc) without
 * libgba. Replaces <gba_types.h> with stdint typedefs.
 *
 * Used only when building as a shared library for tests/host_test.py.
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

#define _gba_types_h_ 1   /* prevents the real header from being pulled in */

#endif
