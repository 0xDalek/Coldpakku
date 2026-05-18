#ifndef SRAM_H
#define SRAM_H

#include <gba_types.h>

#define SRAM_SIZE 0x10000   /* typical 64 KB */

/* GBA SRAM must be accessed one byte at a time (not halfword/word).
 * These wrappers guarantee that. */
void sram_read(u32 off, u8* buf, u32 len);
void sram_write(u32 off, const u8* buf, u32 len);
void sram_wipe(void);

#endif
