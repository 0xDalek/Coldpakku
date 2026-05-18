#ifndef UI_TEXT_H
#define UI_TEXT_H

#include "../types.h"

/*
 * Text rendering on BG0 mode 0 using the libgba console.
 * Screen = 30 columns x 20 rows.
 */

#define TEXT_COLS 30
#define TEXT_ROWS 20

/* Colour schemes (RGB15). After text_init() the default is ORANGE. */
typedef enum {
    TEXT_SCHEME_ORANGE,     /* orange on black (default, "coldpakku" look) */
    TEXT_SCHEME_AMBER,      /* amber on black (CRT IBM 5151) */
    TEXT_SCHEME_PHOSPHOR,   /* P39 phosphor green on black */
    TEXT_SCHEME_DEFAULT,    /* libgba default (blue) */
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

/* ASCII frame around a rectangle. */
void text_box(u32 col, u32 row, u32 width, u32 height);

/* Top status bar with title and right-side status (e.g. "READY"). */
void text_titlebar(const char* title, const char* status);

/* Bottom status line (key hints). */
void text_statusbar(const char* hints);

/* Waits for N VBlanks (~16.7 ms each). Useful in cooperative transitions. */
void text_wait_frames(u32 n);

/* Prints a line with a typewriter effect (1 char/frame). If the user
 * presses any key it flushes the rest at once. */
void text_type_line(u32 col, u32 row, const char* s);

/* Paints the COLDPAKKU logo (6 centred lines, one every 2 frames). The
 * caller then displays the self-tests and the "press any key" screen. */
void text_boot_logo(void);

/* "press any key" wait with a blinking cursor at (28, 17). Returns when
 * the user presses any key, or after `max_frames`. */
void text_press_any_key(u32 max_frames);

#endif
