#include "pin.h"
#include "text.h"
#include "input.h"

#include <gba_input.h>
#include <gba_systemcalls.h>
#include <string.h>
#include <stdio.h>

static void render_chrome(const char* prompt) {
    text_clear();
    text_titlebar("PIN ENTRY", "AUTH");
    text_at(2, 3, prompt);
    text_statusbar("Up/Down digit  L/R move  A add");
}

static void render_field(const u8* digits, int pos, u32 plen) {
    /* row 8: " > [*][*][_][_][_][_][_][_]"
     * row 10: editor for the current digit */
    char field[40];
    memset(field, ' ', sizeof(field));
    int j = 0;
    field[j++] = ' '; field[j++] = '>'; field[j++] = ' ';
    for (u32 i = 0; i < PIN_MAX_LEN; i++) {
        field[j++] = (i == (u32)pos) ? '<' : '[';
        field[j++] = (i < plen) ? '*' : '_';
        field[j++] = (i == (u32)pos) ? '>' : ']';
    }
    field[j] = 0;
    text_at(0, 8, "                              ");
    text_at(0, 8, field);

    char info[40];
    snprintf(info, sizeof(info), "  current digit = %d", digits[pos]);
    text_at(0, 10, "                              ");
    text_at(0, 10, info);

    snprintf(info, sizeof(info), "  length        = %lu / %d",
             (unsigned long)plen, PIN_MAX_LEN);
    text_at(0, 11, "                              ");
    text_at(0, 11, info);

    if (plen >= PIN_MIN_LEN) {
        text_at(2, 13, "  START to confirm");
    } else {
        text_at(2, 13, "                            ");
    }
}

u32 pin_input(char out[PIN_MAX_LEN], const char* prompt) {
    u8 digits[PIN_MAX_LEN] = {0};
    u32 plen = 0;
    int pos = 0;

    int dirty_chrome = 1;
    int dirty_field  = 1;

    for (;;) {
        if (dirty_chrome) { render_chrome(prompt); dirty_chrome = 0; dirty_field = 1; }
        if (dirty_field)  { render_field(digits, pos, plen); dirty_field = 0; }

        VBlankIntrWait();
        input_poll();
        u16 k = input_pressed();
        if (!k) continue;

        if (k & KEY_SELECT) { return 0; }
        if (k & KEY_UP)    { digits[pos] = (digits[pos] + 1) % 10; dirty_field = 1; }
        if (k & KEY_DOWN)  { digits[pos] = (digits[pos] + 9) % 10; dirty_field = 1; }
        if (k & KEY_LEFT)  { if (pos > 0) { pos--; dirty_field = 1; } }
        if (k & KEY_RIGHT) { if (pos < PIN_MAX_LEN - 1) { pos++; dirty_field = 1; } }
        if (k & KEY_A) {
            if (plen < PIN_MAX_LEN) {
                out[plen++] = (char)('0' + digits[pos]);
                if (pos < PIN_MAX_LEN - 1) pos++;
                dirty_field = 1;
            }
        }
        if (k & KEY_B) {
            if (plen > 0) { plen--; dirty_field = 1; }
        }
        if (k & KEY_START) {
            if (plen >= PIN_MIN_LEN) return plen;
        }
    }
}
