#ifndef UI_PROGRESS_H
#define UI_PROGRESS_H

#include <gba_types.h>

void progress_begin(const char* title);
void progress_set(u32 done, u32 total);
void progress_end(void);

/* Adaptador para pasarse como pbkdf2_progress_fn */
void progress_pbkdf2_cb(u32 done, u32 total, void* ud);

#endif
