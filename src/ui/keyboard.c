/*
 * Entrada de 12 palabras BIP39 — modo letter-wheel estilo Ledger.
 *
 *   - Hay un "prefijo" de 0..8 letras que el usuario va construyendo.
 *   - Una de las posiciones del prefijo es la "letra activa" (entre [ ]).
 *   - D-pad arriba/abajo cambia esa letra entre A-Z (carrousel).
 *   - D-pad izq/der mueve el cursor entre posiciones del prefijo.
 *     Si pulsas DERECHA estando en la última posición, se añade una nueva
 *     letra en posicion+1 con valor 'a' por defecto.
 *   - B borra la letra activa (o la última si estás "fuera" del prefijo).
 *   - Cada cambio de prefijo recalcula la lista de candidatas BIP39.
 *   - L/R navegan la lista de candidatas (la "destacada" entre >> [ ] <<).
 *   - A acepta la candidata destacada.
 *   - SELECT vuelve al slot anterior; START cancela toda la sesión.
 *
 * Sin redibujo masivo: dirty-flags por región. Las palabras introducidas
 * NO se ven durante el input. Al final aparece una pantalla REVIEW con
 * las 12 palabras y permite editar cualquiera.
 */
#include "keyboard.h"
#include "text.h"
#include "input.h"
#include "../bip39_wordlist.h"

#include <gba_input.h>
#include <gba_systemcalls.h>
#include <stdio.h>
#include <string.h>

#define MAX_PREFIX 8
#define CANDS_CAP  24       /* 3 columnas x 8 filas en el grid */

/* Resultado de input_one_word(): */
#define IOW_PICKED  1
#define IOW_BACK    2       /* SELECT pulsado, vuelve al slot anterior */
#define IOW_CANCEL  0       /* START pulsado, cancela toda la sesion */

/* === renderers ============================================================ */

static void render_chrome(void) {
    text_clear();
    text_titlebar("BIP39 INPUT", "WORDS");
    text_statusbar("Up/Dn letter L/R cand A pick B del");
}

static void render_slot(int slot) {
    char buf[32];
    snprintf(buf, sizeof(buf), "  word [%2d/12]", slot + 1);
    text_at(0, 2, buf);
}

static void render_wheel(const char* prefix, u32 plen, u32 cur_pos) {
    text_clear_lines(4, 4);
    char buf[40];
    int j = 0;
    buf[j++] = ' '; buf[j++] = ' '; buf[j++] = '>'; buf[j++] = ' ';
    for (u32 i = 0; i < plen && j < 36; i++) {
        if (i == cur_pos) {
            buf[j++] = '['; buf[j++] = prefix[i]; buf[j++] = ']';
        } else {
            buf[j++] = ' '; buf[j++] = prefix[i]; buf[j++] = ' ';
        }
    }
    if (cur_pos == plen && j < 36) {
        buf[j++] = '['; buf[j++] = '_'; buf[j++] = ']';
    }
    buf[j] = 0;
    text_at(0, 4, buf);
}

static void render_cands(const char* prefix, u32 plen,
                         const u16* cands, u32 ncands_total, u32 ncands_shown,
                         u32 highlight) {
    text_clear_lines(6, 14);

    char buf[40];
    if (ncands_total == 0) {
        text_at(2, 6, "no matches yet");
        return;
    }
    /* Si el prefijo coincide EXACTAMENTE con la primera palabra (siempre
     * orden alfabetico, siempre cands[0]), avisamos para que el usuario
     * sepa que puede pulsar A sin teclear mas. Caso clasico: 'can'. */
    int exact = (plen > 0 && ncands_total > 0 &&
                 strcmp(prefix, BIP39_WORDS[cands[0]]) == 0);
    if (exact) {
        snprintf(buf, sizeof(buf), "  %lu match%s  (EXACT: A=%s)",
                 (unsigned long)ncands_total, ncands_total == 1 ? "" : "es",
                 BIP39_WORDS[cands[0]]);
    } else {
        snprintf(buf, sizeof(buf), "  %lu match%s",
                 (unsigned long)ncands_total, ncands_total == 1 ? "" : "es");
    }
    text_at(0, 6, buf);

    /* grid 3 cols x 8 filas, celda 10 chars (8 letra max + [/] o spaces) */
    const u32 COLS = 3;
    for (u32 i = 0; i < ncands_shown; i++) {
        u32 row = 7 + (i / COLS);
        u32 col = (i % COLS) * 10;
        const char* w = BIP39_WORDS[cands[i]];
        if (i == highlight) {
            snprintf(buf, sizeof(buf), "[%-8s]", w);
        } else {
            snprintf(buf, sizeof(buf), " %-8s ", w);
        }
        text_at(col, row, buf);
    }
    if (ncands_total > ncands_shown) {
        snprintf(buf, sizeof(buf), "  +%lu more (refine prefix)",
                 (unsigned long)(ncands_total - ncands_shown));
        text_at(0, 14, buf);
    }
}

static void render_pick(const u16* cands, u32 ncands, u32 highlight) {
    text_clear_line(16);
    if (ncands == 0) {
        text_at(0, 16, "  ---");
        return;
    }
    char buf[40];
    snprintf(buf, sizeof(buf), "  >> [ %-8s ] <<",
             BIP39_WORDS[cands[highlight]]);
    text_at(0, 16, buf);
}

/* === input loop para una sola palabra ===================================== */

static int input_one_word(int slot_display, u16* out_picked) {
    char prefix[MAX_PREFIX + 1] = {0};
    u32  plen = 0;
    u32  cur_pos = 0;
    u16  cands[CANDS_CAP];
    u32  ncands_total = 0;
    u32  ncands_shown = 0;
    u32  highlight = 0;

    int dirty_chrome = 1, dirty_slot = 1, dirty_wheel = 1, dirty_cands = 1, dirty_pick = 1;

    for (;;) {
        if (dirty_chrome) { render_chrome(); dirty_chrome = 0; dirty_slot = dirty_wheel = dirty_cands = dirty_pick = 1; }
        if (dirty_slot)   { render_slot(slot_display); dirty_slot = 0; }
        if (dirty_wheel)  { render_wheel(prefix, plen, cur_pos); dirty_wheel = 0; }
        if (dirty_cands)  {
            ncands_total = bip39_filter_prefix(plen ? prefix : "",
                                               CANDS_CAP, cands);
            ncands_shown = ncands_total > CANDS_CAP ? CANDS_CAP : ncands_total;
            if (highlight >= ncands_shown) highlight = 0;
            render_cands(prefix, plen, cands, ncands_total, ncands_shown, highlight);
            dirty_cands = 0; dirty_pick = 1;
        }
        if (dirty_pick)   { render_pick(cands, ncands_shown, highlight); dirty_pick = 0; }

        VBlankIntrWait();
        input_poll();
        u16 k = input_pressed();
        if (!k) continue;

        if (k & KEY_START)  return IOW_CANCEL;
        if (k & KEY_SELECT) return IOW_BACK;

        if ((k & KEY_UP) || (k & KEY_DOWN)) {
            int delta = (k & KEY_UP) ? +1 : -1;
            if (cur_pos == plen) {
                /* Crear nueva letra: empezar en la primera letra valida
                 * en orden alfabetico (no necesariamente 'a' — ej. tras
                 * "qu" la primera valida es 'a' pero tras "ze" no hay
                 * ninguna y degeneraria). */
                if (plen < MAX_PREFIX) {
                    int found = 0;
                    for (int t = 0; t < 26; t++) {
                        prefix[plen]     = (char)('a' + t);
                        prefix[plen + 1] = 0;
                        if (bip39_has_prefix(prefix)) { found = 1; break; }
                    }
                    if (found) {
                        plen++;
                    } else {
                        prefix[plen] = 0;   /* deja como estaba */
                    }
                }
            } else {
                /* Editar letra existente: itera saltando letras que no
                 * tengan ninguna palabra BIP39 con el prefijo resultante.
                 * Asi nunca se ve "cb..." cuando ninguna palabra empieza
                 * por cb. Proba hasta 26 letras; si ninguna funciona,
                 * deja la letra como estaba. */
                int original = prefix[cur_pos] - 'a';
                int c = original;
                int found = 0;
                for (int tries = 0; tries < 26; tries++) {
                    c = (c + delta + 26) % 26;
                    prefix[cur_pos] = (char)('a' + c);
                    if (bip39_has_prefix(prefix)) { found = 1; break; }
                }
                if (!found) {
                    prefix[cur_pos] = (char)('a' + original);
                }
            }
            dirty_wheel = 1; dirty_cands = 1;
        }
        if (k & KEY_LEFT)  { if (cur_pos > 0) { cur_pos--; dirty_wheel = 1; } }
        if (k & KEY_RIGHT) {
            if (cur_pos < plen) { cur_pos++; dirty_wheel = 1; }
            else if (plen < MAX_PREFIX) {
                /* Misma logica que UP/DOWN al crear letra: arrancar en la
                 * primera letra valida, no en 'a' a ciegas. */
                int found = 0;
                for (int t = 0; t < 26; t++) {
                    prefix[plen]     = (char)('a' + t);
                    prefix[plen + 1] = 0;
                    if (bip39_has_prefix(prefix)) { found = 1; break; }
                }
                if (found) {
                    plen++;
                    cur_pos = plen - 1;
                    dirty_wheel = 1; dirty_cands = 1;
                } else {
                    prefix[plen] = 0;
                }
            }
        }
        if (k & KEY_B) {
            if (plen > 0) {
                u32 del = cur_pos < plen ? cur_pos : plen - 1;
                memmove(&prefix[del], &prefix[del + 1], plen - del);
                plen--;
                if (cur_pos > plen) cur_pos = plen;
                dirty_wheel = 1; dirty_cands = 1;
            }
        }
        if ((k & KEY_L) && ncands_shown > 1) {
            highlight = (highlight + ncands_shown - 1) % ncands_shown;
            dirty_cands = 1;
        }
        if ((k & KEY_R) && ncands_shown > 1) {
            highlight = (highlight + 1) % ncands_shown;
            dirty_cands = 1;
        }
        if (k & KEY_A) {
            if (ncands_total == 0 || ncands_total > CANDS_CAP) continue;
            *out_picked = cands[highlight];
            return IOW_PICKED;
        }
    }
}

/* === REVIEW screen ======================================================== */

static int review_screen(const u16* idx, int* edit_slot) {
    int dirty = 1;
    int hl = -1;       /* >=0 = modo "elegir slot" */
    while (1) {
        if (dirty) {
            text_clear();
            text_titlebar("BIP39 REVIEW", "12/12");
            text_at(0, 2, "  Verify all 12 words:");
            for (int i = 0; i < 12; i++) {
                int row = 4 + (i % 6);
                int col = (i / 6) * 15;
                char cell[20];
                if (i == hl) {
                    snprintf(cell, sizeof(cell), "[%2d:%-8s]", i + 1, BIP39_WORDS[idx[i]]);
                } else {
                    snprintf(cell, sizeof(cell), " %2d:%-8s ", i + 1, BIP39_WORDS[idx[i]]);
                }
                text_at(col, row, cell);
            }
            if (hl < 0) {
                text_statusbar("A confirm  SEL pick slot  B back");
            } else {
                text_statusbar("DPad move  A edit selected  B cancel");
            }
            dirty = 0;
        }
        VBlankIntrWait();
        input_poll();
        u16 k = input_pressed();
        if (!k) continue;

        if (hl < 0) {
            if (k & KEY_A)      { return 1; }
            if (k & KEY_B)      { *edit_slot = 11; return 0; }
            if (k & KEY_SELECT) { hl = 0; dirty = 1; }
        } else {
            if (k & KEY_LEFT)  { if (hl >= 6) { hl -= 6; dirty = 1; } }
            if (k & KEY_RIGHT) { if (hl < 6)  { hl += 6; dirty = 1; } }
            if (k & KEY_UP)    { if (hl % 6) { hl--;     dirty = 1; } }
            if (k & KEY_DOWN)  { if (hl % 6 != 5) { hl++; dirty = 1; } }
            if (k & KEY_A)     { *edit_slot = hl; return 0; }
            if (k & KEY_B)     { hl = -1; dirty = 1; }
        }
    }
}

/* === entry point ========================================================== */

int keyboard_input_words(u16 out_idx[BIP39_WORDS_COUNT]) {
    int slot = 0;
    while (slot < BIP39_WORDS_COUNT) {
        u16 picked = 0;
        int rv = input_one_word(slot, &picked);
        if (rv == IOW_CANCEL) { text_clear(); return 0; }
        if (rv == IOW_BACK)   { if (slot > 0) slot--; continue; }
        out_idx[slot++] = picked;
    }

    /* REVIEW + edit loop */
    for (;;) {
        int edit_slot = 0;
        int rv = review_screen(out_idx, &edit_slot);
        if (rv == 1) {
            if (bip39_validate_words(out_idx)) return 1;
            text_clear();
            text_titlebar("BIP39 REVIEW", "ERROR");
            text_at(2, 6, "!! checksum invalido");
            text_at(2, 8, "  alguna palabra no");
            text_at(2, 9, "  coincide con tu wallet.");
            text_statusbar("SEL re-review  B back to slot 12");
            for (;;) {
                VBlankIntrWait();
                input_poll();
                u16 k = input_pressed();
                if (k & KEY_SELECT) break;
                if (k & KEY_B)      { edit_slot = 11; goto edit; }
            }
            continue;
        }
edit:
        ; /* edita el slot indicado */
        u16 picked = 0;
        int er = input_one_word(edit_slot, &picked);
        if (er == IOW_CANCEL) { text_clear(); return 0; }
        if (er == IOW_PICKED) out_idx[edit_slot] = picked;
        /* IOW_BACK desde edit-mode: simplemente vuelve al review */
    }
}
