#include "sram.h"

/* SRAM mapeada en 0x0E000000. Acceso obligatoriamente byte-a-byte.
 * Marca SRAM en cabecera ROM: ver gba_save_type_marker.s */
static volatile u8* const SRAM = (volatile u8*)0x0E000000;

void sram_read(u32 off, u8* buf, u32 len) {
    for (u32 i = 0; i < len; i++) buf[i] = SRAM[off + i];
}

void sram_write(u32 off, const u8* buf, u32 len) {
    for (u32 i = 0; i < len; i++) SRAM[off + i] = buf[i];
}

void sram_wipe(void) {
    for (u32 i = 0; i < SRAM_SIZE; i++) SRAM[i] = 0xFF;
}
