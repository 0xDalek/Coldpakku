#include "text.h"

#include <gba_console.h>
#include <gba_video.h>
#include <gba_systemcalls.h>
#include <gba_input.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

/*
 * libgba's consoleDemoInit() loads its font in charblock 0, mapbase 4,
 * BG0, using palette 15. The background colour is in BG_COLORS[0] and
 * the text colour is in BG_COLORS[15*16 + 1] = BG_COLORS[241].
 */
#define BG_TEXT_INDEX 241

void text_init(void) {
    consoleDemoInit();
    text_set_scheme(TEXT_SCHEME_ORANGE);
}

void text_set_scheme(text_scheme s) {
    switch (s) {
    case TEXT_SCHEME_ORANGE:
        BG_COLORS[0]            = RGB5(0, 0, 0);
        BG_COLORS[BG_TEXT_INDEX]= RGB5(31, 14, 2);  /* vibrant orange */
        break;
    case TEXT_SCHEME_AMBER:
        BG_COLORS[0]            = RGB5(0, 0, 0);
        BG_COLORS[BG_TEXT_INDEX]= RGB5(31, 22, 4);  /* IBM 5151 amber */
        break;
    case TEXT_SCHEME_PHOSPHOR:
        BG_COLORS[0]            = RGB5(0, 0, 0);
        BG_COLORS[BG_TEXT_INDEX]= RGB5(4, 31, 8);   /* P39 phosphor green */
        break;
    case TEXT_SCHEME_DEFAULT:
    default:
        BG_COLORS[0]            = RGB8(58, 110, 165);
        BG_COLORS[BG_TEXT_INDEX]= RGB5(31, 31, 31);
        break;
    }
}

/* --- clear and positioning helpers ---------------------------------------- */

void text_clear(void) {
    iprintf("\x1b[2J");
}

/* libgba bug: the handler for the ANSI sequence `\x1b[ROW;COLH` writes
 * the 1-based values directly into its internal consoleY/X which are
 * 0-based (see third_party/libgba/src/console.c case 'H'). So sending
 * "\x1b[1;1H" (ANSI 1-based for row=0 col=0) actually places the cursor
 * at row=1 col=1. Symptom: every text_at(0, ...) shifted the content
 * one column to the right and col 0 was left empty, visible only on
 * full-width separators (the `===` and `---` of the titlebar/statusbar
 * "ate" 1 char on the left).
 *
 * Workaround: we pass 0-based coords DIRECTLY without the +1 ANSI
 * requires. libgba accepts them and uses them as-is, so the cursor
 * lands in the correct cell. If libgba ever fixes its H parser, all of
 * our text will shift one cell up-left, which is easy to spot. */
static void goto_xy(u32 col, u32 row) {
    iprintf("\x1b[%lu;%luH", (unsigned long)row, (unsigned long)col);
}

void text_clear_line(u32 row) {
    /* Only TEXT_COLS-1 = 29 chars: writing AT col 29 can cause the
     * libgba console to wrap to the next row (side effect: cursor left
     * in an overflow state, future prints could leak). */
    char blanks[TEXT_COLS];
    memset(blanks, ' ', TEXT_COLS - 1);
    blanks[TEXT_COLS - 1] = 0;
    goto_xy(0, row);
    iprintf("%s", blanks);
}

void text_clear_lines(u32 row_from, u32 row_to_inclusive) {
    for (u32 r = row_from; r <= row_to_inclusive && r < TEXT_ROWS; r++) text_clear_line(r);
}

void text_clear_rect(u32 col, u32 row, u32 width, u32 height) {
    if (col >= TEXT_COLS) return;
    if (col + width > TEXT_COLS) width = TEXT_COLS - col;
    char blanks[TEXT_COLS + 1];
    memset(blanks, ' ', width);
    blanks[width] = 0;
    for (u32 r = 0; r < height && row + r < TEXT_ROWS; r++) {
        goto_xy(col, row + r);
        iprintf("%s", blanks);
    }
}

void text_at(u32 col, u32 row, const char* s) {
    goto_xy(col, row);
    iprintf("%s", s);
}

void text_printf_at(u32 col, u32 row, const char* fmt, ...) {
    char buf[80];
    va_list ap;
    va_start(ap, fmt);
    vsiprintf(buf, fmt, ap);
    va_end(ap);
    goto_xy(col, row);
    iprintf("%s", buf);
}

void text_hex(u32 col, u32 row, const u8* data, u32 len) {
    static const char* hex = "0123456789abcdef";
    char buf[80];
    u32 j = 0;
    for (u32 i = 0; i < len && j + 2 < sizeof(buf); i++) {
        buf[j++] = hex[(data[i] >> 4) & 0x0F];
        buf[j++] = hex[data[i] & 0x0F];
    }
    buf[j] = 0;
    text_at(col, row, buf);
}

void text_hex_short(u32 col, u32 row, const u8* data, u32 len,
                    u32 head, u32 tail) {
    static const char* hex = "0123456789abcdef";
    char buf[80];
    u32 j = 0;
    for (u32 i = 0; i < head && i < len; i++) {
        buf[j++] = hex[(data[i] >> 4) & 0x0F];
        buf[j++] = hex[data[i] & 0x0F];
    }
    if (head + tail < len) {
        buf[j++] = '.'; buf[j++] = '.'; buf[j++] = '.';
        for (u32 i = len - tail; i < len; i++) {
            buf[j++] = hex[(data[i] >> 4) & 0x0F];
            buf[j++] = hex[data[i] & 0x0F];
        }
    } else {
        for (u32 i = head; i < len; i++) {
            buf[j++] = hex[(data[i] >> 4) & 0x0F];
            buf[j++] = hex[data[i] & 0x0F];
        }
    }
    buf[j] = 0;
    text_at(col, row, buf);
}

/* --- ASCII frames --------------------------------------------------------- */

void text_box(u32 col, u32 row, u32 width, u32 height) {
    if (width < 2 || height < 2) return;
    char top[TEXT_COLS + 1], mid[TEXT_COLS + 1], bot[TEXT_COLS + 1];
    if (width > TEXT_COLS) width = TEXT_COLS;

    top[0] = '+';
    for (u32 i = 1; i < width - 1; i++) top[i] = '-';
    top[width - 1] = '+'; top[width] = 0;

    mid[0] = '|';
    for (u32 i = 1; i < width - 1; i++) mid[i] = ' ';
    mid[width - 1] = '|'; mid[width] = 0;

    memcpy(bot, top, width + 1);

    text_at(col, row, top);
    for (u32 r = 1; r < height - 1; r++) text_at(col, row + r, mid);
    text_at(col, row + height - 1, bot);
}

/* --- status bars ---------------------------------------------------------- */

/* Some libgba console builds wrap to the next row when you WRITE AT the
 * last column (col 29 with TEXT_COLS=30). To prevent the last char of
 * the titlebar/statusbar leaking onto the adjacent row we use
 * TEXT_COLS-1 chars wide. Cost: one blank column on the right edge. */
#define TEXT_SAFE_WIDTH  (TEXT_COLS - 1)

void text_titlebar(const char* title, const char* status) {
    /* Row 0: [TITLE] ............... [STATUS]
       Row 1: separator "==============" */
    text_clear_line(0);
    text_clear_line(1);
    char buf[TEXT_COLS + 1];
    u32 tlen = strlen(title);
    u32 slen = status ? strlen(status) : 0;

    /* clamp */
    if (tlen > TEXT_SAFE_WIDTH - 4) tlen = TEXT_SAFE_WIDTH - 4;
    memset(buf, ' ', TEXT_SAFE_WIDTH); buf[TEXT_SAFE_WIDTH] = 0;
    buf[0] = '['; memcpy(buf + 1, title, tlen); buf[1 + tlen] = ']';
    if (slen) {
        if (slen > 8) slen = 8;
        u32 right_start = TEXT_SAFE_WIDTH - (slen + 2);
        buf[right_start] = '[';
        memcpy(buf + right_start + 1, status, slen);
        buf[right_start + 1 + slen] = ']';
    }
    text_at(0, 0, buf);

    char sep[TEXT_COLS + 1];
    for (u32 i = 0; i < TEXT_SAFE_WIDTH; i++) sep[i] = '=';
    sep[TEXT_SAFE_WIDTH] = 0;
    text_at(0, 1, sep);
}

void text_statusbar(const char* hints) {
    char sep[TEXT_COLS + 1];
    for (u32 i = 0; i < TEXT_SAFE_WIDTH; i++) sep[i] = '-';
    sep[TEXT_SAFE_WIDTH] = 0;
    text_at(0, TEXT_ROWS - 2, sep);
    text_clear_line(TEXT_ROWS - 1);
    text_at(0, TEXT_ROWS - 1, hints);
}

/* --- terminal-style boot splash ------------------------------------------- */

/* "cartridge label" style boot banner:
 *   +---------------------------+
 *   ||                         ||
 *   ||  C O L D P A K K U      ||
 *   ||  ethereum wallet v0.1   ||
 *   ||                         ||
 *   +---------------------------+
 *
 * IMPORTANT: each string must be EXACTLY 29 chars (TEXT_COLS - 1) to
 * avoid the libgba console wrap when writing the char at col 29: in
 * some builds the last char jumps to col 0 of the next row, which used
 * to print "+ and right column on the left" and ate the first dash of
 * the top frame. Same workaround as the TEXT_SAFE_WIDTH in text_titlebar.
 */
static const char* const BANNER[] = {
    "+---------------------------+",
    "||                         ||",
    "||  C O L D P A K K U      ||",
    "||  ethereum wallet v0.1   ||",
    "||                         ||",
    "+---------------------------+",
    NULL
};

void text_wait_frames(u32 n) {
    for (u32 i = 0; i < n; i++) VBlankIntrWait();
}

/* Prints a line with a "typewriter" effect: one character per frame.
 * If get_keys() returns anything, skips the effect and flushes the rest
 * at once. */
void text_type_line(u32 col, u32 row, const char* s) {
    char buf[TEXT_COLS + 1];
    u32 len = 0;
    while (s[len] && len < TEXT_COLS) len++;
    if (col + len > TEXT_COLS) len = TEXT_COLS - col;
    for (u32 i = 0; i < len; i++) {
        buf[i] = s[i];
        buf[i + 1] = 0;
        text_at(col, row, buf);
        VBlankIntrWait();
        scanKeys();
        if (keysDown()) {
            /* user is in a hurry: flush the rest */
            memcpy(buf, s, len);
            buf[len] = 0;
            text_at(col, row, buf);
            return;
        }
    }
}

void text_boot_logo(void) {
    text_clear();
    /* "cartridge label" logo: 6 lines, one every 2 frames */
    int row = 1;
    for (int i = 0; BANNER[i]; i++) {
        text_at(0, row + i, BANNER[i]);
        text_wait_frames(2);
    }
}

void text_press_any_key(u32 max_frames) {
    text_at(0, 17, "  > press any key to begin");
    int blink = 1;
    for (u32 frames = 0; frames < max_frames; frames++) {
        VBlankIntrWait();
        if ((frames & 15) == 0) {
            text_at(28, 17, blink ? "_" : " ");
            blink = !blink;
        }
        scanKeys();
        if (keysDown()) break;
    }
}
