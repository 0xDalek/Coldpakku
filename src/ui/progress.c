#include "progress.h"
#include "text.h"

#include <gba_systemcalls.h>
#include <stdio.h>
#include <string.h>

#define BAR_W 24

static u32 last_filled = 0xFFFFFFFFu;
static u32 spinner_phase = 0;
static u32 spinner_frame = 0;

/* General variant: the caller decides the screen title and the
 * statusbar subtitle. Use this for SIGN, BIP32, etc. */
void progress_begin_full(const char* screen_title,
                         const char* status_subtitle,
                         const char* line1,
                         const char* line2,
                         const char* line3) {
    text_clear();
    text_titlebar(screen_title ? screen_title : "PROCESSING", "BUSY");
    if (line1) text_at(2, 4, line1);
    if (line2) text_at(2, 5, line2);
    text_at(2, 8, "[                        ]");
    text_at(2, 11, "0 / 0          ");
    if (line3) text_at(2, 13, line3);
    text_statusbar(status_subtitle ? status_subtitle : "working...");
    last_filled = 0xFFFFFFFFu;
}

void progress_begin(const char* title) {
    progress_begin_full("DERIVATION", "computing PBKDF2-HMAC-SHA512",
                        title, NULL, "  please wait...");
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
    /* counter and spinner always */
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
