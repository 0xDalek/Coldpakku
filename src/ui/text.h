#ifndef UI_TEXT_H
#define UI_TEXT_H

#include "../types.h"

/*
 * Renderizado de texto en BG0 modo 0 con la consola de libgba.
 * Pantalla = 30 columnas x 20 filas.
 */

#define TEXT_COLS 30
#define TEXT_ROWS 20

/* Esquemas de color (RGB15). El de phosphor green es el default tras text_init. */
typedef enum {
    TEXT_SCHEME_PHOSPHOR,   /* verde sobre negro (default) */
    TEXT_SCHEME_AMBER,      /* ámbar sobre negro (CRT IBM) */
    TEXT_SCHEME_DEFAULT,    /* libgba default (azul) */
} text_scheme;

void text_init(void);
void text_set_scheme(text_scheme s);

void text_clear(void);
void text_clear_line(u32 row);
void text_clear_lines(u32 row_from, u32 row_to_inclusive);
void text_clear_rect(u32 col, u32 row, u32 width, u32 height);

void text_at(u32 col, u32 row, const char* s);
void text_printf_at(u32 col, u32 row, const char* fmt, ...);
void text_hex(u32 col, u32 row, const u8* data, u32 len);
void text_hex_short(u32 col, u32 row, const u8* data, u32 len, u32 head, u32 tail);

/* Marco ASCII alrededor de un rectángulo. */
void text_box(u32 col, u32 row, u32 width, u32 height);

/* Barra de estado superior con título y subtítulo a la derecha (e.g. "READY"). */
void text_titlebar(const char* title, const char* status);

/* Línea de status inferior (atajos de teclas). */
void text_statusbar(const char* hints);

/* Banner ASCII art de boot con efecto typewriter (espera vblanks entre líneas). */
void text_boot_banner(void);

#endif
