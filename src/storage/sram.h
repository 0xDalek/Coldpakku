#ifndef SRAM_H
#define SRAM_H

#include <gba_types.h>

#define SRAM_SIZE 0x10000   /* 64 KB típico */

/* SRAM en GBA debe accederse byte a byte (no halfword/word). Estos wrappers
 * lo garantizan. */
void sram_read(u32 off, u8* buf, u32 len);
void sram_write(u32 off, const u8* buf, u32 len);
void sram_wipe(void);

#endif
