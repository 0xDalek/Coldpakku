#ifndef UI_PROGRESS_H
#define UI_PROGRESS_H

#include <gba_types.h>

void progress_begin(const char* title);

/* General variant: the caller controls the title, the statusbar, and up
 * to 3 lines of descriptive text. Use for BIP32 derive, signing, etc. */
void progress_begin_full(const char* screen_title,
                         const char* status_subtitle,
                         const char* line1,
                         const char* line2,
                         const char* line3);

void progress_set(u32 done, u32 total);
void progress_end(void);

/* Adapter to pass as a pbkdf2_progress_fn / bip32_progress_fn (same
 * signature: u32 done, u32 total, void* ud). */
void progress_pbkdf2_cb(u32 done, u32 total, void* ud);

#endif
