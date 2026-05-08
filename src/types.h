#ifndef GBA_SIGNER_TYPES_H
#define GBA_SIGNER_TYPES_H

#include <gba_types.h>
#include <stdint.h>

/* libgba's gba_types.h define u8/u16/u32 pero no u64/s64. Lo añadimos aquí
 * para que todo el proyecto pueda incluir un único header tipográfico. */
typedef uint64_t u64;
typedef int64_t  s64;

#endif
