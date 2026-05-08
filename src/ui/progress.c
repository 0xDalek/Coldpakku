#include "progress.h"
#include "text.h"

#include <gba_systemcalls.h>
#include <stdio.h>
#include <string.h>

#define BAR_W 24

static u32 last_filled = 0xFFFFFFFFu;
static u32 spinner_phase = 0;
static u32 spinner_frame = 0;

void progress_begin(const char* title) {
    text_clear();
    text_titlebar("DERIVATION", "BUSY");
    text_at(2, 4, title);
    text_at(2, 8, "[                        ]");
    text_at(2, 11, "0 / 0          ");
    text_at(2, 13, "  please wait...");
    text_statusbar("computing PBKDF2-HMAC-SHA512");
    last_filled = 0xFFFFFFFFu;
}

void progress_set(u32 done, u32 total) {
    if (total == 0) total = 1;
    u32 filled = (done * BAR_W) / total;
    if (filled != last_filled) {
        char bar[BAR_W + 1];
        for (u32 i = 0; i < BAR_W; i++) bar[i] = (i < filled) ? '#' : ((i == filled) ? '>' : ' ');
        bar[BAR_W] = 0;
        text_at(3, 8, bar);
        last_filled = filled;
    }
    /* contador y spinner siempre */
    char buf[24];
    snprintf(buf, sizeof(buf), "%lu / %lu     ", (unsigned long)done, (unsigned long)total);
    text_at(2, 11, buf);
    if ((spinner_frame++ & 7) == 0) {
        static const char spin[] = "|/-\\";
        char s[3] = { spin[spinner_phase & 3], 0, 0 };
        text_at(28, 0, s);
        spinner_phase++;
    }
}

void progress_end(void) {
    text_at(28, 0, " ");
}

void progress_pbkdf2_cb(u32 done, u32 total, void* ud) {
    (void)ud;
    progress_set(done, total);
}
