/*
 * High-level state machine of Coldpakku:
 *
 *   BOOT -> (saved?) DECRYPT_PIN -> READY
 *               \-> NEW_SESSION -> WORDS -> DERIVE -> SAVE? -> READY
 *   READY -> wait UART -> CONFIRM -> SIGN -> READY
 */
#include "state.h"

#include "ui/text.h"
#include "ui/input.h"
#include "ui/keyboard.h"
#include "ui/pin.h"
#include "ui/progress.h"
#include "ui/confirm.h"
#include "ui/splash.h"
#include "ui/chains.h"
#include "crypto/bip39.h"
#include "crypto/bip32.h"
#include "crypto/ethereum.h"
#include "crypto/eth_tx.h"
#include "crypto/keccak256.h"
#include "crypto/eip712.h"
#include "crypto/uecc_rng.h"
#include "storage/session.h"
#include "storage/policy.h"
#include "storage/sram.h"
#include "link/uart.h"
#include "link/protocol.h"
#include "link/tx_meta.h"

#include <gba_input.h>
#include <gba_systemcalls.h>
#include <stdio.h>
#include <string.h>

/* RAM-only secret material; zeroize aggressively. */
static u8 g_seed[64];
static bip32_node g_node;
static u8 g_address[20];
static int g_ready = 0;

/* Counter of TXs / messages signed since the last session unlock.
 * RAM-only (resets on every PIN unlock or new session); avoids any extra
 * SRAM wear.
 *
 * Incremented on EVERY successful signature (sign_tx, personal_sign,
 * typed_data), NOT on GET_ADDRESS or cancellations. Rendered in the
 * AWAITING TRANSACTION screen so the user has a reference. */
static u32 g_signed_count = 0;

/* === Chain lock policy ====================================================
 * Index (into chains_at()) of the EVM network the GBA is "locked" to.
 * A tx arriving over UART with a different chainId is REJECTED locally
 * (without going through the CONFIRM screen) and PROTO_REJECT_CHAIN is
 * returned to the host. The user changes it with LEFT/RIGHT on the
 * AWAITING TRANSACTION (READY) screen; each change is persisted to SRAM
 * via policy_save().
 *
 * Factory default is Ethereum mainnet (chain_id 1). If SRAM already has
 * a saved policy, that one wins.
 * ======================================================================== */
static u32 g_active_chain_idx = 0;
#define DEFAULT_CHAIN_ID 1u   /* Ethereum mainnet */

static void wipe_secrets(void) {
    memset(g_seed, 0, sizeof(g_seed));
    memset(&g_node, 0, sizeof(g_node));
    g_ready = 0;
    g_signed_count = 0;
}

static int derive_from_seed(void) {
    /* This is what makes the GBA "appear frozen" after the PIN is entered:
     * 5 levels of BIP32 (HMAC-SHA512 + secp256k1 point multiplication) +
     * the final address derivation. Each step ~1-3 s on GBA hardware,
     * total ~10-15 s. We show a progress screen with a bar that advances
     * step by step so the user can see we're still alive. */
    progress_begin_full(
        "DERIVING WALLET", "BIP32 m/44'/60'/0'/0/0",
        "  deriving eth address",
        "  ~10-15s on GBA hardware",
        "  step:");
    bip32_node master;
    bip32_master(g_seed, &master);
    progress_set(0, 6);  /* stage 0: master ready */

    if (!bip32_derive_eth_default_progress(&master, &g_node,
                                           progress_pbkdf2_cb, NULL)) {
        memset(&master, 0, sizeof(master));
        progress_end();
        return 0;
    }
    /* Now the address derivation (secp256k1 base-point mul + keccak). */
    progress_set(5, 6);
    if (!eth_priv_to_address(g_node.priv, g_address, NULL)) {
        memset(&master, 0, sizeof(master));
        progress_end();
        return 0;
    }
    progress_set(6, 6);
    memset(&master, 0, sizeof(master));
    g_ready = 1;
    progress_end();
    return 1;
}

static void info_screen(const char* title, const char* status,
                        const char* line1, const char* line2) {
    text_clear();
    text_titlebar(title, status);
    if (line1) text_at(2, 6, line1);
    if (line2) text_at(2, 8, line2);
    text_statusbar("press any key");
    VBlankIntrWait();
    /* small debounce */
    for (int i = 0; i < 30; i++) VBlankIntrWait();
}

static int try_load_session(void) {
    char pin[PIN_MAX_LEN];
    for (int attempt = 0; attempt < 3; attempt++) {
        u32 plen = pin_input(pin, "Saved session. PIN?");
        if (!plen) {
            memset(pin, 0, PIN_MAX_LEN);
            return 0;
        }
        /* session_load (v3) verifies the PIN's HMAC after an expensive
         * KDF (PBKDF2-HMAC-SHA512, 10000 iters). If the PIN is wrong it
         * does NOT decrypt and returns 0. If the blob is still in v2
         * format (single SHA256) it is migrated to v3 inside session_load
         * — the user pays for one extra PBKDF2 this one time. */
        progress_begin("Deriving key (PBKDF2)");
        int ok = session_load(pin, plen, g_seed, progress_pbkdf2_cb, NULL);
        progress_end();
        if (!ok) {
            char hint[24];
            snprintf(hint, sizeof(hint), "  attempts left: %d", 2 - attempt);
            info_screen("PIN", "FAIL", "!! wrong PIN", hint);
            continue;
        }
        if (!derive_from_seed()) {
            info_screen("PIN", "ERR", "!! BIP32 derive failed", NULL);
            wipe_secrets();
            memset(pin, 0, PIN_MAX_LEN);
            return 0;
        }
        confirm_show_address(g_address);
        if (confirm_yes_no("Address correct?")) {
            memset(pin, 0, PIN_MAX_LEN);
            return 1;
        }
        /* The displayed address is NOT the expected one. Since the MAC
         * already validated the PIN, this means the SRAM is corrupt or
         * this is NOT the wallet the user expected (seed change?).
         * Better to abort. */
        wipe_secrets();
        info_screen("PIN", "ABORT",
                    "!! address mismatch",
                    "  SRAM corrupt or seed changed");
        memset(pin, 0, PIN_MAX_LEN);
        return 0;
    }
    info_screen("PIN", "WIPE", "!! 3 failed attempts", "  wiping SRAM...");
    session_wipe();
    memset(pin, 0, PIN_MAX_LEN);
    return 0;
}

static int input_new_session(void) {
    u16 widx[BIP39_WORDS_COUNT];
    if (!keyboard_input_words(widx)) return 0;

    char mnemonic[BIP39_MNEMONIC_MAX_LEN];
    u32 mlen = bip39_build_mnemonic(widx, mnemonic);
    memset(widx, 0, sizeof(widx));

    progress_begin("PBKDF2-HMAC-SHA512 (2048)");
    bip39_mnemonic_to_seed(mnemonic, mlen, "", 0,
                           g_seed, progress_pbkdf2_cb, NULL);
    /* zeroize mnemonic in RAM before doing anything else */
    memset(mnemonic, 0, sizeof(mnemonic));
    progress_end();

    if (!derive_from_seed()) {
        info_screen("DERIVE", "ERR", "!! BIP32 derive failed", NULL);
        wipe_secrets();
        return 0;
    }
    confirm_show_address(g_address);

    if (confirm_yes_no("Save session to SRAM?")) {
        char pin[PIN_MAX_LEN];
        u32 plen = pin_input(pin, "Set a new PIN:");
        if (plen) {
            progress_begin("Deriving key (PBKDF2)");
            session_save(g_seed, pin, plen, progress_pbkdf2_cb, NULL);
            progress_end();
            memset(pin, 0, PIN_MAX_LEN);
            info_screen("SESSION", "SAVE",
                        "  >> stored in SRAM",
                        "  PBKDF2 + ChaCha20 + HMAC");
        }
    }
    return 1;
}

/* Paints ONLY the network selector block (rows 13-17 + sprite). Called
 * from render_ready_screen and, separately, when the user navigates with
 * the L/R triggers or LEFT/RIGHT on the d-pad. Keeping it isolated allows
 * partial refresh without flickering the rest of the screen.
 *
 * Layout (30 cols x 20 rows):
 *
 *   row 13:  network lock:
 *   row 14:        [16x16 ICON sprite at (112, 112), centred]
 *   row 15:
 *   row 16:    < BASE  Base                      >
 *   row 17:        chainId 8453        ETH
 *
 * For testnets we append " (test)" after the name, so it's obvious at a
 * glance that this is not the production chain (important: never sign
 * on mainnet thinking you were on Sepolia or vice versa).
 */
/* Partial render of the network selector. Called from render_ready_screen
 * (initial paint) and from the L/R handler (partial update without a full
 * clear). Occupies rows 7-8: the first row has label + abbr/name + arrows,
 * the second row has chainId + native symbol on the right. */
#define CHAIN_ROW 7

static void render_chain_selector(void) {
    const chain_info* ci = chains_at(g_active_chain_idx);
    if (!ci) ci = chains_unknown();

    text_clear_line(CHAIN_ROW);
    text_clear_line(CHAIN_ROW + 1);

    /* Row 7: < ABBR Name (t) > — selector with arrows hinting that it's
     * navigable with L/R. The "(t)" marks testnets at a glance.
     *
     * Row 8: chainId N         SYM — numeric confirmation + native
     * symbol (ETH/POL/BNB/...) aligned to the right. */
    char line[40];
    const char* tflag = ci->is_testnet ? " (t)" : "";
    snprintf(line, sizeof(line), "  < %-4s %s%s",
             ci->abbr, ci->name, tflag);
    text_at(0, CHAIN_ROW, line);
    /* Right arrow at col 27-28 (not col 28-29) to avoid the libgba
     * console wrap when writing AT the last column. */
    text_at(27, CHAIN_ROW, " >");

    snprintf(line, sizeof(line), "    chainId %lu",
             (unsigned long)ci->chain_id);
    text_at(0, CHAIN_ROW + 1, line);
    /* Native symbol pinned to the right edge with 1 col of margin (some
     * libgba console implementations wrap when writing AT the last col,
     * so we leave col 29 free as a defence). */
    char sym[8];
    snprintf(sym, sizeof(sym), "%s", ci->native_sym);
    u32 sym_len = (u32)strlen(sym);
    u32 sym_col = (TEXT_COLS > sym_len + 1) ? (TEXT_COLS - 1 - sym_len) : 24;
    text_at((int)sym_col, CHAIN_ROW + 1, sym);
}

/* === Link indicator with the extension / Pico ===========================
 * The GBA pulses READY every 0.5 s; the host (extension via Pico) replies
 * when it has something (sign tx, query, heartbeat). Each ACK received
 * marks "host seen". The indicator on AWAITING TRANSACTION reflects:
 *
 *   ACTIVE  — activity <10s ago (heartbeat or any recent query)
 *   idle    — 10..60s without activity (extension alive but idle, or
 *             slow polling interval)
 *   NONE !  — >60s without activity (probably the cable is unplugged
 *             or the extension is closed). Blinks to draw attention.
 *
 * The frame counter `g_main_frame` is ONLY incremented inside the
 * AWAITING loop (not in handlers or confirm). That prevents a 5 s
 * signing operation from "tricking" the elapsed counter without the
 * host actually sending anything.
 * ======================================================================== */
typedef enum { LINK_NONE, LINK_IDLE, LINK_ACTIVE } link_state_t;

static u32          g_main_frame      = 0;
static u32          g_last_host_seen  = 0;
static int          g_host_ever_seen  = 0;   /* false at boot — link OFFLINE until the first ACK */
static link_state_t g_link_state      = LINK_NONE;

/* The extension runs a setInterval(5s) in its offscreen page that sends
 * PROTO_HEARTBEAT to the GBA. With a 10 s ACTIVE window we detect unplug
 * in <10s (worst case: ~10s after disconnect). NONE fires at 20 s (3-4
 * failed heartbeats). */
#define LINK_ACTIVE_FRAMES (60 * 10)   /* <10s -> ACTIVE (OK)   */
#define LINK_IDLE_FRAMES   (60 * 20)   /* <20s -> idle, else NONE */

static link_state_t link_state_for(u32 elapsed_frames) {
    if (elapsed_frames < LINK_ACTIVE_FRAMES) return LINK_ACTIVE;
    if (elapsed_frames < LINK_IDLE_FRAMES)   return LINK_IDLE;
    return LINK_NONE;
}

/* Paints only row 10 (label "link" + value). blink_on only affects
 * LINK_NONE (alternates "OFFLINE !" / "offline  " every ~0.5s — subtle
 * but noticeable blink, without exceeding TEXT_COLS to avoid wrapping
 * onto row 11). */
#define LINK_ROW 10

static void render_link_indicator(link_state_t s, int blink_on) {
    text_clear_line(LINK_ROW);
    switch (s) {
    case LINK_ACTIVE:
        text_at(0, LINK_ROW, "  link       OK");
        break;
    case LINK_IDLE:
        text_at(0, LINK_ROW, "  link       idle");
        break;
    case LINK_NONE:
        text_at(0, LINK_ROW, blink_on
            ? "  link       OFFLINE !"
            : "  link       offline  ");
        break;
    }
}

/* AWAITING TRANSACTION layout:
 *
 *   [COLDPAKKU]            [READY]      row 0-1 (titlebar)
 *   ==============================
 *                                         row 2  (blank)
 *     account                              row 3
 *     0x9858effd232b4033e47d                row 4
 *     90003d41ec34ecaeda94                  row 5
 *                                         row 6  (blank)
 *     network   < ETH Mainnet      >       row 7  \  chain selector
 *               chainId 1          ETH     row 8  /
 *                                         row 9  (blank)
 *     link       OK                        row 10 (link indicator)
 *     signed     0 this session            row 11
 *                                         row 12 (blank)
 *                                         row 13 (blank)
 *         >> AWAITING TX <<                row 14 (highlighted status)
 *                                         row 15-17 (blank)
 *   ------------------------------         row 18 (statusbar separator)
 *   L/R chain  |  START lock               row 19 (statusbar)
 */
static void render_ready_screen(const char* status) {
    text_clear();
    text_titlebar("COLDPAKKU", status);

    /* === ACCOUNT === */
    text_at(0, 3, "  account");
    text_at(0, 4, "  0x");
    text_hex(4, 4, g_address, 10);
    text_hex(4, 5, g_address + 10, 10);

    /* === NETWORK (rows 7-8) === */
    render_chain_selector();

    /* === LINK + SIGNED === */
    render_link_indicator(g_link_state, 1);

    char buf[40];
    snprintf(buf, sizeof(buf), "  signed     %lu this session",
             (unsigned long)g_signed_count);
    text_at(0, 11, buf);

    /* === Highlighted status === */
    text_at(0, 14, "       >> AWAITING TX <<");

    text_statusbar("L/R chain | START | SEL wipe");
}

/* "SIGNING..." screen shown just before invoking uECC's ECDSA.
 * uECC is atomic: once inside, the GBA "appears frozen" for 3-7s while
 * computing the signature. Painting this message first prevents the user
 * from thinking it has crashed. A real spinner is not possible (there
 * are no yields). */
static void render_signing_screen(const char* what) {
    text_clear();
    text_titlebar("SIGNING", "BUSY");
    text_at(2, 4, "  computing ECDSA secp256k1");
    text_at(2, 5, "  on Game Boy Advance hw");
    char buf[40];
    snprintf(buf, sizeof(buf), "  what: %s", what);
    text_at(2, 7, buf);
    text_at(2, 9, "  takes about 3-7 seconds");
    text_at(2, 10, "  the screen will look frozen");
    text_at(2, 11, "  until the signature is ready");
    text_at(2, 13, "  please wait...");
    text_at(2, 16, "  [#### working ####]");
    text_statusbar("uECC point multiplications");
    /* force a VBlank so the frame paints before we block */
    VBlankIntrWait();
}

/* === Boot self-tests ====================================================
 * Real (not decorative) checks shown with a typewriter effect right
 * after the logo. If any fails the user sees it on screen; we do not
 * abort automatically so as not to leave the GBA stuck.
 * ======================================================================== */

/* Forward declaration of the public micro-ecc API for the link test.
 * Avoids #including a third_party header from state.c. */
struct uECC_Curve_t;
extern const struct uECC_Curve_t* uECC_secp256k1(void);

static int selftest_rom_header(void) {
    /* gbafix CRC at byte 0xBD of the header. CRC = -(0x19 + sum(0xA0..0xBC)).
     * The BIOS already validates the Nintendo logo (0x04..0x9F) during
     * boot; if it failed we wouldn't even be running. */
    const u8* rom = (const u8*)0x08000000;
    u32 sum = 0x19;
    for (u32 i = 0xA0; i <= 0xBC; i++) sum += rom[i];
    u8 expected = (u8)((~sum + 1) & 0xff);
    return rom[0xBD] == expected;
}

static int selftest_sram_probe(void) {
    /* Scratch slot at offset 200, outside the session blob [0..117] and
     * the policy [1024..1038]. Write/read/restore — non-destructive. */
    const u32 offset = 200;
    u8 orig;
    sram_read(offset, &orig, 1);
    u8 magic = 0x5A;
    sram_write(offset, &magic, 1);
    u8 readback;
    sram_read(offset, &readback, 1);
    sram_write(offset, &orig, 1);  /* restore */
    return readback == magic;
}

static int selftest_keccak(void) {
    /* keccak256("abc") = 4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45 */
    u8 out[32];
    keccak256((const u8*)"abc", 3, out);
    static const u8 expected[32] = {
        0x4e,0x03,0x65,0x7a,0xea,0x45,0xa9,0x4f,
        0xc7,0xd4,0x7b,0xa8,0x26,0xc8,0xd6,0x67,
        0xc0,0xd1,0xe6,0xe3,0x3a,0x64,0xa0,0x36,
        0xec,0x44,0xf5,0x8f,0xa1,0x2d,0x6c,0x45,
    };
    return memcmp(out, expected, 32) == 0;
}

static int selftest_uecc_linked(void) {
    /* Sanity: the lib is linked and the curve exists. We don't run a
     * point-mul here (3-5s, too long for boot). The real uECC usage
     * during signing would fail visibly with a clear message if the
     * curve were corrupt, so we don't need an exhaustive boot test. */
    return uECC_secp256k1() != NULL;
}

/* Prints "  <label_dots>[<result>]" with a typewriter effect. label_dots
 * must include its own trailing "...." for alignment. result is "[ ok ]"
 * if passed, "[FAIL]" if not. */
static void type_test_result(u32 row, const char* label_dots, int passed) {
    char line[40];
    snprintf(line, sizeof(line), "  %s[%s]",
             label_dots, passed ? " ok " : "FAIL");
    text_type_line(0, row, line);
}

static void run_boot_self_test(void) {
    text_boot_logo();
    text_wait_frames(10);

    text_at(0, 9, "  -- coldboot self-test --");
    text_wait_frames(6);

    type_test_result(10, "rom header........", selftest_rom_header());
    type_test_result(11, "sram probe........", selftest_sram_probe());
    type_test_result(12, "uecc/secp256k1....", selftest_uecc_linked());
    type_test_result(13, "keccak vectors....", selftest_keccak());

    /* Link cable: the real check (heartbeat with the extension) happens
     * at runtime on the AWAITING TRANSACTION screen. We can't know if
     * there's a host here because the extension only talks when it has
     * something to say. */
    text_type_line(0, 14, "  link cable........[wait]");

    text_wait_frames(15);
    text_press_any_key(60 * 4);
}

/* Static buffers for incoming payloads. They live in EWRAM, they don't
 * touch the IWRAM stack. We reuse g_rlp_buf as a general buffer: opcodes
 * are processed one at a time so there's no overlap. For typed_data we
 * have dedicated buffers (the hashes are small but the text can grow up
 * to 4 KB, and v7 also adds the TLV tree + decoded tree table). */
#include <gba_base.h>   /* EWRAM_BSS attribute for big workspaces */
static EWRAM_BSS u8 g_rlp_buf[PROTO_TX_RLP_MAX];
static EWRAM_BSS u8 g_typed_text_buf[PROTO_TYPED_TEXT_MAX];
static EWRAM_BSS u8 g_meta_buf[PROTO_TX_META_MAX];

/* v7: receive buffer for the EIP-712 TLV tree (up to 8 KB) plus the
 * decoded type table (~6.4 KB). Both live in EWRAM — IWRAM is reserved
 * for the working stack and small hot caches. */
static EWRAM_BSS u8 g_typed_tree_buf[PROTO_TYPED_TREE_MAX];
static EWRAM_BSS eip712_tree_t g_eip712_tree;

/* Cooperatively waits for the host to send PROTO_TXRESULT and shows the
 * result screen. If the host sends nothing in ~30s or the user presses
 * B, returns without showing it (compatible with old hosts).
 *
 * Why cooperative: the host can take several seconds to broadcast (RPC
 * roundtrip + pool entry). Meanwhile the spinner must stay alive and the
 * user must be able to cancel.
 *
 * Controlled race condition: the host has already seen our DONE and,
 * after a brief sleep, sends PROTO_TXRESULT. Because the SIO RX FIFO
 * only holds 4 bytes the host sleeps 50ms (see pc/protocol.py
 * send_tx_result) so we have time to paint the screen and enter the loop
 * before the first byte arrives. Even so, the first byte fits in the
 * FIFO. */
static void await_and_show_tx_result(void) {
    confirm_show_broadcasting();

    /* Cooperative spinner at (28, 10). Same coords as awaiting tx for
     * visual coherence. */
    int spin_phase = 0;
    int spin_frame = 0;
    static const char spinner[] = "|/-\\";

    /* Total timeout of 30s. The host normally answers in <2s, but a
     * slow RPC (mainnet under load) can take longer. */
    const u32 TIMEOUT_FRAMES = 60 * 30;
    u32 frames = 0;

    int got_opcode = 0;
    for (;;) {
        VBlankIntrWait();
        input_poll();

        if ((++spin_frame & 7) == 0) {
            char s[2] = { spinner[(spin_phase++) & 3], 0 };
            text_at(28, 10, s);
        }

        if (input_pressed() & KEY_B) return;       /* user does not want to wait */

        int b = uart_try_recv_byte();
        if (b < 0) {
            if (++frames > TIMEOUT_FRAMES) return; /* host did not respond */
            continue;
        }
        if (b != PROTO_TXRESULT) continue;          /* garbage, ignore */
        got_opcode = 1;
        break;
    }
    if (!got_opcode) return;

    /* From here on we expect the payload with a short per-byte timeout
     * (1s) using busy-spin to drain the FIFO without losing bytes. */
    int st = uart_recv_byte_busy(60);
    if (st < 0) return;
    u8 status = (u8)st;

    u8  hash[32];
    char errmsg[TXRESULT_ERRMSG_MAX];
    u32 errlen = 0;
    memset(hash, 0, sizeof(hash));
    memset(errmsg, 0, sizeof(errmsg));

    if (status == TXRESULT_BROADCAST_OK || status == TXRESULT_NO_BROADCAST) {
        for (int i = 0; i < 32; i++) {
            int hh = uart_recv_byte_busy(60);
            if (hh < 0) return;
            hash[i] = (u8)hh;
        }
    } else if (status == TXRESULT_BROADCAST_ERR) {
        int ln = uart_recv_byte_busy(60);
        if (ln < 0) return;
        u32 mlen = (u32)ln;
        if (mlen > TXRESULT_ERRMSG_MAX) mlen = TXRESULT_ERRMSG_MAX;
        for (u32 i = 0; i < mlen; i++) {
            int mm = uart_recv_byte_busy(60);
            if (mm < 0) return;
            errmsg[i] = (char)mm;
        }
        errlen = mlen;
    } else {
        /* unknown status: show as a generic error */
        const char* m = "unknown status from host";
        u32 mlen = 0;
        while (m[mlen]) mlen++;
        memcpy(errmsg, m, mlen);
        errlen = mlen;
        status = TXRESULT_BROADCAST_ERR;
    }

    confirm_show_tx_result(status, hash, errmsg, errlen);
}

/* === Opcode dispatchers (v4) ===
 * Each one assumes the opcode has already been read and that the host
 * is sending the payload. Return 1 if a tx was signed (caller must wait
 * for TXRESULT), 0 in any other case (cancel, error, get_address,
 * personal_sign, typed_data). */

/* Rejection screen for chain mismatch. The GBA is locked to X and the
 * tx came in with chainId Y. We do NOT sign and the normal confirm is
 * not shown. The extension receives PROTO_REJECT_CHAIN with both
 * chainIds and warns the dapp.
 *
 * Explicit design: red-feeling screen (large ! icon, WRONG status) with
 * info on both networks and a hint "L/R on READY to switch". */
static void render_wrong_chain_screen(const chain_info* expected,
                                      u64 got_chain_id) {
    text_clear();
    text_titlebar("TX REJECTED", "WRONG");

    text_at(2, 3, "!! CHAIN LOCK MISMATCH");

    text_at(2, 6, "  GBA is locked to:");
    char line[40];
    snprintf(line, sizeof(line), "    %-4s  %s",
             expected->abbr, expected->name);
    text_at(0, 7, line);
    snprintf(line, sizeof(line), "    chainId %lu",
             (unsigned long)expected->chain_id);
    text_at(0, 8, line);

    text_at(2, 10, "  But tx was for chainId:");
    /* If we recognise the tx's chainId, also show its name; otherwise
     * just the number. */
    const chain_info* got_ci = chains_lookup((u32)got_chain_id);
    if (got_ci) {
        snprintf(line, sizeof(line), "    %-4s  %s",
                 got_ci->abbr, got_ci->name);
        text_at(0, 11, line);
        snprintf(line, sizeof(line), "    chainId %lu",
                 (unsigned long)got_chain_id);
        text_at(0, 12, line);
    } else {
        snprintf(line, sizeof(line), "    chainId %lu  (unknown)",
                 (unsigned long)got_chain_id);
        text_at(0, 11, line);
    }

    text_at(2, 14, "  Signature REJECTED.");
    text_at(2, 16, "  Use L/R on READY to");
    text_at(2, 17, "  switch the GBA chain.");

    text_statusbar("press any key to dismiss");

    /* Wait for the user up to 90 frames (1.5s) or until they press
     * anything, so the rejection is visible even if the host is slow to
     * process the packet. */
    for (int i = 0; i < 90; i++) {
        VBlankIntrWait(); input_poll();
        if (input_pressed()) break;
    }
}

/* Common handler for PROTO_TX_RLP (with_meta=0) and PROTO_TX_RLP_META
 * (with_meta=1). The opcode has already been consumed by the caller;
 * here we just read the rest of the payload, parse it, and run the
 * confirm. */
static int handle_tx_rlp_common(int with_meta) {
    u32 rlp_len = 0;
    if (!protocol_recv_lenprefixed(g_rlp_buf, sizeof(g_rlp_buf),
                                   PROTO_TX_RLP_MAX, &rlp_len)) {
        text_at(2, 13, "!! link/timeout error    ");
        return 0;
    }

    tx_meta meta;
    tx_meta_init(&meta);
    if (with_meta) {
        u32 meta_len = 0;
        if (!protocol_recv_lenprefixed_2b(g_meta_buf, sizeof(g_meta_buf),
                                          PROTO_TX_META_MAX, &meta_len)) {
            text_at(2, 13, "!! link/meta error       ");
            return 0;
        }
        /* Tolerant parser: if the meta is malformed we do NOT abort, we
         * just ignore it. The GBA can still display the tx with minimal
         * info from the RLP. */
        if (!tx_meta_parse(g_meta_buf, meta_len, &meta)) {
            tx_meta_init(&meta);
        }
    }

    eth_tx tx;
    if (!eth_tx_decode(g_rlp_buf, rlp_len, &tx)) {
        text_clear();
        text_titlebar("CONFIRM TX", "ERR");
        text_at(2, 6, "!! malformed tx");
        text_at(2, 8, "  RLP decode failed");
        text_statusbar("any key continue");
        for (int i = 0; i < 90; i++) {
            VBlankIntrWait(); input_poll();
            if (input_pressed()) break;
        }
        protocol_send_cancel();
        protocol_send_done();
        return 0;
    }

    /* === Chain lock check ==================================================
     * The GBA is the authority: if the tx is not for the locked chain we
     * do NOT even show the confirmation screen. This prevents a
     * distracted user from signing a tx on mainnet thinking they were on
     * a testnet (a classic source of funds-loss in software wallets).
     *
     * The protocol tells the host WHY we rejected (expected vs got) so
     * the extension can show a useful error to the dapp instead of a
     * generic "user cancelled".
     * ====================================================================== */
    const chain_info* active = chains_at(g_active_chain_idx);
    if (active && tx.chainid != (u64)active->chain_id) {
        render_wrong_chain_screen(active, tx.chainid);
        protocol_send_reject_chain(active->chain_id, (u32)tx.chainid);
        protocol_send_done();
        memset(&tx, 0, sizeof(tx));
        return 0;
    }

    int signed_ok = 0;
    if (confirm_tx(&tx, &meta)) {
        u8 hash[32];
        eth_tx_signing_hash(&tx, hash);
        render_signing_screen("ETH transaction");
        u8 sig[65];
        if (eth_sign_hash(g_node.priv, hash, sig)) {
            protocol_send_sig(sig);
            g_signed_count++;
            signed_ok = 1;
        } else {
            protocol_send_cancel();
        }
        memset(sig, 0, 65);
        memset(hash, 0, 32);
    } else {
        protocol_send_cancel();
    }
    protocol_send_done();
    memset(&tx, 0, sizeof(tx));
    return signed_ok;
}

static int handle_tx_rlp(void)      { return handle_tx_rlp_common(0); }
static int handle_tx_rlp_meta(void) { return handle_tx_rlp_common(1); }

static void handle_get_address(void) {
    /* No user confirmation: it's read-only, equivalent to reading
     * window.ethereum.request({method:'eth_accounts'}). The host has
     * already been authorized to the device via WebSerial. */
    protocol_send_address(g_address);
    protocol_send_done();
}

static void handle_get_policy(void) {
    /* Returns the chain_id the GBA is currently locked to. No
     * confirmation (read-only). The extension calls it on connect to
     * show "GBA: BASE locked" in the popup's badge, and optionally to
     * warn before even sending the tx (defence in depth). */
    const chain_info* ci = chains_at(g_active_chain_idx);
    u32 cid = ci ? ci->chain_id : 0;
    protocol_send_policy(cid);
    protocol_send_done();
}

static void handle_heartbeat(void) {
    /* No payload, no response — ACK + opcode already marked activity via
     * g_last_host_seen. We just close the handshake with DONE so the
     * host knows we arrived. */
    protocol_send_done();
}

static u8 g_origin_buf[META_ORIGIN_MAX];

static void handle_connect_request(void) {
    /* Payload: 2B BE len + N bytes ASCII origin. Read with the 2B
     * variant (which accepts len=0; we'd treat it as "<empty origin>").
     * Max META_ORIGIN_MAX (96 bytes). */
    u32 origin_len = 0;
    if (!protocol_recv_lenprefixed_2b(g_origin_buf, sizeof(g_origin_buf),
                                       META_ORIGIN_MAX, &origin_len)) {
        text_at(2, 13, "!! link/origin error    ");
        protocol_send_cancel();
        protocol_send_done();
        return;
    }

    int approved = confirm_connect_request((const char*)g_origin_buf, origin_len);
    if (approved) {
        protocol_send_connect_ok();
    } else {
        protocol_send_cancel();
    }
    protocol_send_done();
}

/* Generates the ASCII decimal (no null) of a u32. Returns the number of
 * bytes written. */
static u32 u32_to_ascii(u32 v, u8* out) {
    if (v == 0) { out[0] = '0'; return 1; }
    u8 tmp[12]; u32 n = 0;
    while (v) { tmp[n++] = (u8)('0' + (v % 10)); v /= 10; }
    for (u32 i = 0; i < n; i++) out[i] = tmp[n - 1 - i];
    return n;
}

static void handle_personal_sign(void) {
    u32 mlen = 0;
    if (!protocol_recv_lenprefixed(g_rlp_buf, sizeof(g_rlp_buf),
                                   PROTO_PERSONAL_MSG_MAX, &mlen)) {
        protocol_send_cancel();
        protocol_send_done();
        return;
    }

    if (confirm_personal_sign(g_rlp_buf, mlen)) {
        /* EIP-191: hash = keccak256("\x19Ethereum Signed Message:\n<len>" || msg) */
        keccak256_ctx kctx;
        keccak256_init(&kctx);
        static const u8 prefix[] = "\x19" "Ethereum Signed Message:\n";
        keccak256_update(&kctx, prefix, sizeof(prefix) - 1);
        u8 lenstr[12];
        u32 lenstr_n = u32_to_ascii(mlen, lenstr);
        keccak256_update(&kctx, lenstr, lenstr_n);
        keccak256_update(&kctx, g_rlp_buf, mlen);
        u8 hash[32];
        keccak256_final(&kctx, hash);

        render_signing_screen("personal_sign EIP-191");
        u8 sig[65];
        if (eth_sign_hash(g_node.priv, hash, sig)) {
            protocol_send_sig(sig);
            g_signed_count++;
        } else {
            protocol_send_cancel();
        }
        memset(sig, 0, 65);
        memset(hash, 0, 32);
        memset(&kctx, 0, sizeof(kctx));
    } else {
        protocol_send_cancel();
    }
    protocol_send_done();
}

static void handle_typed_data(void) {
    u8 ds[32], mh[32];
    int ok_ds = 1, ok_mh = 1;
    /* Busy-spin read of the two hashes: 64 bytes back-to-back. */
    for (int i = 0; i < 32; i++) {
        int b = uart_recv_byte_busy(PROTO_TX_TIMEOUT_FRAMES);
        if (b < 0) { ok_ds = 0; break; }
        ds[i] = (u8)b;
    }
    if (ok_ds) {
        for (int i = 0; i < 32; i++) {
            int b = uart_recv_byte_busy(PROTO_TX_TIMEOUT_FRAMES);
            if (b < 0) { ok_mh = 0; break; }
            mh[i] = (u8)b;
        }
    }
    if (!ok_ds || !ok_mh) {
        protocol_send_cancel();
        protocol_send_done();
        return;
    }

    u32 tlen = 0;
    if (!protocol_recv_lenprefixed(g_typed_text_buf, sizeof(g_typed_text_buf),
                                   PROTO_TYPED_TEXT_MAX, &tlen)) {
        protocol_send_cancel();
        protocol_send_done();
        return;
    }

    /* v7: optional TLV tree of the typed data so the cartridge can
     * verify the hashes on-device when the user presses L+R. tree_len=0
     * keeps the legacy blind-only flow. The recv helper accepts len=0. */
    u32 tree_len = 0;
    if (!protocol_recv_lenprefixed_2b(g_typed_tree_buf, sizeof(g_typed_tree_buf),
                                      PROTO_TYPED_TREE_MAX, &tree_len)) {
        protocol_send_cancel();
        protocol_send_done();
        return;
    }

    /* Decode the tree (if any) and recompute domainSeparator +
     * messageHash to compare against the host's. The result drives the
     * confirm screen's parsed-view + MISMATCH flow. */
    eip712_status_t parse_status = EIP712_ERR_MALFORMED;
    const eip712_tree_t* tree_ptr = NULL;
    if (tree_len > 0) {
        parse_status = eip712_parse_and_verify(g_typed_tree_buf, tree_len,
                                               ds, mh, &g_eip712_tree);
        if (parse_status == EIP712_OK_MATCH || parse_status == EIP712_OK_MISMATCH) {
            tree_ptr = &g_eip712_tree;
        }
        /* For ERR_* we silently downgrade to blind-only mode. The user
         * still sees the host-supplied hashes + pretty text and decides
         * whether to trust the host. */
    }

    /* v7 chain-lock for typed data: if we successfully decoded a tree
     * AND its EIP712Domain carries a chainId AND that chainId differs
     * from the one this cartridge is locked to, reject the same way as
     * tx_rlp does (REJECT_CHAIN + WRONG CHAIN screen). Tree-less and
     * chainId-less typed data fall through (no enforcement possible). */
    if (tree_ptr && tree_ptr->has_chain_id) {
        const chain_info* active = chains_at(g_active_chain_idx);
        if (active && tree_ptr->domain_chain_id != (u32)active->chain_id) {
            render_wrong_chain_screen(active, (u64)tree_ptr->domain_chain_id);
            protocol_send_reject_chain(active->chain_id, tree_ptr->domain_chain_id);
            protocol_send_done();
            return;
        }
    }

    if (confirm_typed_data((const char*)g_typed_text_buf, tlen, ds, mh,
                           tree_ptr, parse_status)) {
        /* EIP-712: hash = keccak256(0x19 || 0x01 || domainSeparator || messageHash) */
        u8 buf[66];
        buf[0] = 0x19;
        buf[1] = 0x01;
        memcpy(buf + 2, ds, 32);
        memcpy(buf + 34, mh, 32);
        u8 hash[32];
        keccak256(buf, 66, hash);

        render_signing_screen("typed_data EIP-712");
        u8 sig[65];
        if (eth_sign_hash(g_node.priv, hash, sig)) {
            protocol_send_sig(sig);
            g_signed_count++;
        } else {
            protocol_send_cancel();
        }
        memset(sig, 0, 65);
        memset(hash, 0, 32);
        memset(buf, 0, sizeof(buf));
    } else {
        protocol_send_cancel();
    }
    protocol_send_done();
}

static void sign_loop(void) {
    uart_init();
    render_ready_screen("READY");

    int spin_phase = 0;
    int spin_frame = 0;
    static const char spinner[] = "|/-\\";

    /* Main cooperative loop: every VBlank updates the UI, sends a READY
     * every N frames and does a non-blocking peek for an ACK. That way
     * the spinner keeps moving and the user knows the firmware is
     * alive. */
    const u32 READY_PULSE_FRAMES = 30;  /* 0.5s between each READY */
    u32 frames_since_ready = READY_PULSE_FRAMES;  /* forces immediate send */
    int saw_link_error = 0;

    for (;;) {
        VBlankIntrWait();
        input_poll();

        /* spinner every 8 frames (~135ms) — more visible than every 16 */
        if ((++spin_frame & 7) == 0) {
            char s[2] = { spinner[(spin_phase++) & 3], 0 };
            text_at(28, 10, s);
        }

        if (input_pressed() & KEY_START) {
            wipe_secrets();
            text_clear();
            text_titlebar("COLDPAKKU", "LOCK");
            text_at(2, 6, "  >> session locked");
            text_at(2, 8, "  reset to start over");
            text_statusbar("---");
            for (;;) VBlankIntrWait();
        }

        /* SELECT = wipe wallet (destructive). Asks for confirmation with
         * a "hold A 3s" gesture so an accidental press does NOT wipe the
         * wallet. After the wipe the session is as if freshly installed:
         * the next boot will ask for the 12 words from scratch. */
        if (input_pressed() & KEY_SELECT) {
            if (confirm_wipe_wallet()) {
                session_wipe();
                wipe_secrets();
                text_clear();
                text_titlebar("WALLET WIPED", "OK");
                text_at(2, 5, "  >> SRAM erased");
                text_at(2, 7, "  >> RAM keys zeroized");
                text_at(2, 10, "  Power-cycle the GBA to");
                text_at(2, 11, "  re-enter your 12 words");
                text_at(2, 12, "  or set up a new wallet.");
                text_statusbar("---");
                for (;;) VBlankIntrWait();
            }
            /* Cancelled: re-render awaiting-tx to return to the normal state. */
            render_ready_screen("READY");
            continue;
        }

        /* Network selector. We accept the four directional keys:
         *   - L and R   (shoulder triggers)   <- match the statusbar "L/R chain"
         *   - LEFT/RIGHT of the d-pad         <- ergonomic for horizontal play
         * Each change is persisted to SRAM (battery-backed, no flash-like
         * wear) so the lock survives a cartridge reset.
         * Partial screen refresh to avoid flickering the rest of the fields.
         *
         * We use input_held() (level) instead of input_pressed() (edge)
         * to be more tolerant of missed edges + we do an 8-frame manual
         * debounce to avoid too-fast repeats. A short tap fires once;
         * held it scrolls ~7 networks/sec. */
        u16 nav_pressed = input_pressed();
        u16 nav_held    = input_held();
        const u16 PREV_KEYS = KEY_L | KEY_LEFT;
        const u16 NEXT_KEYS = KEY_R | KEY_RIGHT;
        static u32 nav_cooldown = 0;
        if (nav_cooldown > 0) nav_cooldown--;
        u16 nav = nav_pressed | (nav_cooldown == 0 ? nav_held : 0);
        if (nav & (PREV_KEYS | NEXT_KEYS)) {
            u32 n = chains_count();
            if (n > 0) {
                if (nav & PREV_KEYS) {
                    g_active_chain_idx = (g_active_chain_idx + n - 1) % n;
                } else {
                    g_active_chain_idx = (g_active_chain_idx + 1) % n;
                }
                const chain_info* nci = chains_at(g_active_chain_idx);
                if (nci) policy_save(nci->chain_id);
                render_chain_selector();
                nav_cooldown = 8;  /* 8 frames ~= 130ms between repeats if held */
            }
        }

        /* Sends a READY every 0.5s. The host is in perform_signing
         * reading 1 byte until the timeout, so pulsing instead of
         * spamming saves traffic and keeps the TX FIFO clean. */
        if (++frames_since_ready >= READY_PULSE_FRAMES) {
            protocol_send_ready();
            frames_since_ready = 0;
        }

        /* Refresh the 'link:' indicator every ~0.5s. The monotonic frame
         * counter is incremented ONLY here (not in handlers or confirm),
         * so a long signing operation does NOT artificially bump
         * `elapsed`. */
        g_main_frame++;
        if ((g_main_frame & 31) == 0) {
            /* If the host has never been seen since boot, force NONE: the
             * subtraction g_main_frame - g_last_host_seen would give a
             * very small elapsed at the start (both start at 0) and
             * would show a false "OK" until 10s went by without anything
             * arriving. */
            link_state_t ns;
            if (!g_host_ever_seen) {
                ns = LINK_NONE;
            } else {
                u32 elapsed = g_main_frame - g_last_host_seen;
                ns = link_state_for(elapsed);
            }
            int blink_on = ((g_main_frame >> 5) & 1) != 0;
            if (ns != g_link_state) {
                g_link_state = ns;
                render_link_indicator(g_link_state, blink_on);
            } else if (ns == LINK_NONE) {
                /* Refresh blink even if the state did not change. */
                render_link_indicator(g_link_state, blink_on);
            }
        }

        /* Non-blocking peek: has ACK arrived? */
        int b = uart_try_recv_byte();
        if (b < 0) continue;          /* nothing yet, go to next frame */
        if (b != PROTO_ACK) continue; /* garbage, ignore and continue */

        /* ACK received: we mark "host seen" RIGHT NOW (before reading
         * the opcode, in case that fails). That way the indicator stays
         * ACTIVE even if the opcode times out. */
        g_last_host_seen = g_main_frame;
        g_host_ever_seen = 1;

        /* ACK received: read the opcode and dispatch (v4: several
         * opcodes possible). From here on the protocol functions block
         * until the operation is done and we come back to the
         * ready/ack cycle. */
        int op = protocol_recv_opcode();
        if (op < 0) {
            saw_link_error = 1;
            text_at(2, 13, "!! link/timeout error    ");
            continue;
        }
        if (saw_link_error) {
            text_at(2, 13, "                         ");
            saw_link_error = 0;
        }

        /* `ui_touched` controls whether the handler cleared/changed the
         * screen. If YES -> we need to repaint AWAITING TRANSACTION on
         * return. If NO -> we leave the screen intact to avoid a flash
         * of re-render (the extension calls getPolicy/getAddress
         * periodically and previously each call caused a visible
         * text_clear every ~30s). */
        int signed_tx = 0;
        int ui_touched = 0;
        switch ((u8)op) {
            case PROTO_TX_RLP:
                signed_tx = handle_tx_rlp();
                ui_touched = 1;
                break;
            case PROTO_TX_RLP_META:
                signed_tx = handle_tx_rlp_meta();
                ui_touched = 1;
                break;
            case PROTO_GET_ADDRESS:
                /* read-only, does not change UI */
                handle_get_address();
                break;
            case PROTO_PERSONAL_SIGN:
                handle_personal_sign();
                ui_touched = 1;
                break;
            case PROTO_TYPED_DATA:
                handle_typed_data();
                ui_touched = 1;
                break;
            case PROTO_GET_POLICY:
                /* read-only, does not change UI */
                handle_get_policy();
                break;
            case PROTO_HEARTBEAT:
                /* presence only, does not change UI */
                handle_heartbeat();
                break;
            case PROTO_CONNECT_REQUEST:
                /* shows CONNECT REQUEST screen, waits for A/B */
                handle_connect_request();
                ui_touched = 1;
                break;
            default:
                /* unknown opcode: cancel politely so the host knows
                 * something failed. */
                protocol_send_cancel();
                protocol_send_done();
                break;
        }

        /* Only the tx path has a TXRESULT phase (broadcast feedback).
         * The rest go back to awaiting transaction directly. */
        if (signed_tx) {
            await_and_show_tx_result();
            ui_touched = 1;  /* the TX RESULT screen cleared it */
        }

        if (ui_touched) {
            render_ready_screen("READY");
        }
    }
}

void wallet_run(void) {
    /* important: input_init first -> enables IRQs and the VBlank handler
     * that VBlankIntrWait needs inside the banner / splash. */
    input_init();
    uecc_register_rng();

    /* splash: bitmap of the COLDPAKKU cartridge (~3.5s or any key) */
    splash_show(60 * 4);

    /* after splash: reinitialise text mode (mode 0 + libgba console) */
    text_init();

    /* Load the chain lock policy from SRAM. If there is no saved policy
     * (first boot, erased SRAM, or corrupted blob) we use Ethereum
     * mainnet as a safe default and persist it so the next boot already
     * has a valid blob. */
    u32 saved_chain = DEFAULT_CHAIN_ID;
    if (!policy_load(&saved_chain)) {
        saved_chain = DEFAULT_CHAIN_ID;
        policy_save(saved_chain);
    }
    int idx = chains_index_of(saved_chain);
    if (idx < 0) idx = chains_index_of(DEFAULT_CHAIN_ID);
    if (idx < 0) idx = 0;
    g_active_chain_idx = (u32)idx;

    run_boot_self_test();

    for (;;) {
        text_clear();
        text_titlebar("COLDPAKKU", "BOOT");
        text_at(2, 6, "  >> probing SRAM...");
        text_statusbar("v0.1  |  cold boot");
        for (int i = 0; i < 20; i++) VBlankIntrWait();

        int loaded = 0;
        if (session_present()) {
            text_at(2, 8, "  >> session found");
            for (int i = 0; i < 20; i++) VBlankIntrWait();
            loaded = try_load_session();
        }
        if (!loaded) {
            if (!input_new_session()) {
                wipe_secrets();
                continue;
            }
        }
        sign_loop();
    }
}
