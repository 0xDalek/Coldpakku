#include "text.h"

#include <gba_console.h>
#include <gba_video.h>
#include <gba_systemcalls.h>
#include <gba_input.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

/*
 * libgba consoleDemoInit() carga su font en charblock 0, mapbase 4, BG0,
 * usando palette 15. El color de fondo está en BG_COLORS[0] y el del
 * texto en BG_COLORS[15*16 + 1] = BG_COLORS[241].
 */
#define BG_TEXT_INDEX 241

void text_init(void) {
    consoleDemoInit();
    text_set_scheme(TEXT_SCHEME_PHOSPHOR);
}

void text_set_scheme(text_scheme s) {
    switch (s) {
    case TEXT_SCHEME_PHOSPHOR:
        BG_COLORS[0]            = RGB5(0, 0, 0);
        BG_COLORS[BG_TEXT_INDEX]= RGB5(4, 31, 8);   /* P39 phosphor green */
        break;
    case TEXT_SCHEME_AMBER:
        BG_COLORS[0]            = RGB5(0, 0, 0);
        BG_COLORS[BG_TEXT_INDEX]= RGB5(31, 22, 4);  /* IBM 5151 amber */
        break;
    case TEXT_SCHEME_DEFAULT:
    default:
        BG_COLORS[0]            = RGB8(58, 110, 165);
        BG_COLORS[BG_TEXT_INDEX]= RGB5(31, 31, 31);
        break;
    }
}

/* --- helpers de borrado y posicionamiento --------------------------------- */

void text_clear(void) {
    iprintf("\x1b[2J");
}

static void goto_xy(u32 col, u32 row) {
    iprintf("\x1b[%lu;%luH", (unsigned long)(row + 1), (unsigned long)(col + 1));
}

void text_clear_line(u32 row) {
    char blanks[TEXT_COLS + 1];
    memset(blanks, ' ', TEXT_COLS);
    blanks[TEXT_COLS] = 0;
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

/* --- marcos ASCII --------------------------------------------------------- */

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

/* --- barras de status ----------------------------------------------------- */

void text_titlebar(const char* title, const char* status) {
    /* Línea 0: [TITLE] ............... [STATUS]
       Línea 1: separador "==============" */
    text_clear_line(0);
    text_clear_line(1);
    char buf[TEXT_COLS + 1];
    u32 tlen = strlen(title);
    u32 slen = status ? strlen(status) : 0;

    /* limita */
    if (tlen > TEXT_COLS - 4) tlen = TEXT_COLS - 4;
    memset(buf, ' ', TEXT_COLS); buf[TEXT_COLS] = 0;
    buf[0] = '['; memcpy(buf + 1, title, tlen); buf[1 + tlen] = ']';
    if (slen) {
        if (slen > 8) slen = 8;
        u32 right_start = TEXT_COLS - (slen + 2);
        buf[right_start] = '[';
        memcpy(buf + right_start + 1, status, slen);
        buf[right_start + 1 + slen] = ']';
    }
    text_at(0, 0, buf);

    char sep[TEXT_COLS + 1];
    for (u32 i = 0; i < TEXT_COLS; i++) sep[i] = '=';
    sep[TEXT_COLS] = 0;
    text_at(0, 1, sep);
}

void text_statusbar(const char* hints) {
    char sep[TEXT_COLS + 1];
    for (u32 i = 0; i < TEXT_COLS; i++) sep[i] = '-';
    sep[TEXT_COLS] = 0;
    text_at(0, TEXT_ROWS - 2, sep);
    text_clear_line(TEXT_ROWS - 1);
    text_at(0, TEXT_ROWS - 1, hints);
}

/* --- splash de boot estilo terminal --------------------------------------- */

static const char* const BANNER[] = {
    "  _____ _____  ___       _____",
    " / ____|  __ \\|   |     /     \\",
    "| |  __| |__) |   |____|  ___  |",
    "| | |_ |  _  /| |   ___|  ___  |",
    "| |__| | |_) || |  |    \\ \\_/  /",
    " \\_____|____/ |_|  |     \\____/",
    "                                ",
    "      H A R D W A R E   W A L L",
    NULL
};

static void wait_frames(u32 n) {
    for (u32 i = 0; i < n; i++) VBlankIntrWait();
}

void text_boot_banner(void) {
    text_clear();
    /* línea por línea con pequeño retardo: efecto typewriter de cargo cult */
    int row = 2;
    for (int i = 0; BANNER[i]; i++) {
        text_at(0, row + i, BANNER[i]);
        wait_frames(3);
    }
    /* prompt simulado */
    wait_frames(20);
    text_at(0, 13, "> ROM checksum.....[ OK ]");
    wait_frames(15);
    text_at(0, 14, "> SRAM probe.......[ OK ]");
    wait_frames(15);
    text_at(0, 15, "> Crypto self-test.[ OK ]");
    wait_frames(15);
    text_at(0, 16, "> Link cable.......[idle]");
    wait_frames(20);
    text_at(0, 18, "  press any key to begin_");
    /* parpadeo del cursor para hint visual */
    int blink = 1;
    for (int frames = 0; frames < 60 * 3; frames++) {
        VBlankIntrWait();
        if ((frames & 31) == 0) {
            text_at(24, 18, blink ? "_" : " ");
            blink = !blink;
        }
        scanKeys();
        if (keysDown()) break;
    }
}
