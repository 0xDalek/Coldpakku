#ifndef GBA_SIGNER_TYPES_H
#define GBA_SIGNER_TYPES_H

#include <gba_types.h>
#include <stdint.h>

/* libgba's gba_types.h defines u8/u16/u32 but not u64/s64. We add them
 * here so the whole project can include a single typedef header. */
typedef uint64_t u64;
typedef int64_t  s64;

#endif
