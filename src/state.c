/*
 * State machine de alto nivel del GBA Signer:
 *
 *   BOOT -> (sav?) DECRYPT_PIN -> READY
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
#include "crypto/bip39.h"
#include "crypto/bip32.h"
#include "crypto/ethereum.h"
#include "crypto/eth_tx.h"
#include "crypto/uecc_rng.h"
#include "storage/session.h"
#include "link/uart.h"
#include "link/protocol.h"

#include <gba_input.h>
#include <gba_systemcalls.h>
#include <stdio.h>
#include <string.h>

/* RAM-only secret material; zeroizar agresivamente. */
static u8 g_seed[64];
static bip32_node g_node;
static u8 g_address[20];
static int g_ready = 0;

static void wipe_secrets(void) {
    memset(g_seed, 0, sizeof(g_seed));
    memset(&g_node, 0, sizeof(g_node));
    g_ready = 0;
}

static int derive_from_seed(void) {
    bip32_node master;
    bip32_master(g_seed, &master);
    if (!bip32_derive_eth_default(&master, &g_node)) {
        memset(&master, 0, sizeof(master));
        return 0;
    }
    if (!eth_priv_to_address(g_node.priv, g_address, NULL)) {
        memset(&master, 0, sizeof(master));
        return 0;
    }
    memset(&master, 0, sizeof(master));
    g_ready = 1;
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
    /* pequeño debounce */
    for (int i = 0; i < 30; i++) VBlankIntrWait();
}

static int try_load_session(void) {
    char pin[PIN_MAX_LEN];
    for (int attempt = 0; attempt < 3; attempt++) {
        u32 plen = pin_input(pin, "Sesion guardada. PIN?");
        if (!plen) {
            memset(pin, 0, PIN_MAX_LEN);
            return 0;
        }
        /* session_load (v2) verifica HMAC del PIN: si el PIN es incorrecto,
         * NO descifra y NO devuelve seed basura — devuelve 0 y mostramos el
         * error real. Antes esto fallaba silenciosamente y derivaba una
         * wallet "fantasma" diferente segun el PIN, lo que confundia al
         * usuario y era un riesgo de perdida de fondos. */
        if (!session_load(pin, plen, g_seed)) {
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
        if (confirm_yes_no("Direccion correcta?")) {
            memset(pin, 0, PIN_MAX_LEN);
            return 1;
        }
        /* Address mostrada NO es la esperada. Como el MAC ya valido el PIN,
         * esto significa que la SRAM esta corrupta o esto NO es la wallet
         * que el usuario esperaba (cambio de seed?). Mejor abortar. */
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
    /* zeroizar mnemonic en RAM antes de hacer cualquier otra cosa */
    memset(mnemonic, 0, sizeof(mnemonic));
    progress_end();

    if (!derive_from_seed()) {
        info_screen("DERIVE", "ERR", "!! BIP32 derive failed", NULL);
        wipe_secrets();
        return 0;
    }
    confirm_show_address(g_address);

    if (confirm_yes_no("Guardar sesion en SRAM?")) {
        char pin[PIN_MAX_LEN];
        u32 plen = pin_input(pin, "Define un PIN nuevo:");
        if (plen) {
            session_save(g_seed, pin, plen);
            memset(pin, 0, PIN_MAX_LEN);
            info_screen("SESSION", "SAVE", "  >> stored in SRAM", "  encrypted ChaCha20");
        }
    }
    return 1;
}

static void render_ready_screen(const char* status) {
    text_clear();
    text_titlebar("GBA SIGNER", status);
    text_at(0, 3, "  link: UART 115200 8N1");
    text_at(0, 5, "  account:");
    text_at(0, 6, "  0x");
    text_hex(4, 6, g_address, 10);
    text_hex(4, 7, g_address + 10, 10);
    text_at(0, 10, "  awaiting transaction...");
    text_statusbar("START lock + wipe key");
}

/* Buffer estático para la tx RLP entrante. Vive en EWRAM, no toca el stack
 * de IWRAM. */
static u8 g_rlp_buf[PROTO_TX_RLP_MAX];

/* Espera (cooperativamente) a que el host envie PROTO_TXRESULT y muestra
 * la pantalla resultado. Si el host no envia nada en ~30s o el usuario
 * pulsa B, vuelve sin mostrarla (compatibilidad con hosts antiguos).
 *
 * Por que cooperativo: el host puede tardar varios segundos en hacer
 * broadcast (RPC roundtrip + pool entry). Mientras tanto el spinner debe
 * seguir vivo y el usuario debe poder cancelar.
 *
 * Race condition controlada: el host ya ha visto nuestro DONE y, tras un
 * breve sleep, manda PROTO_TXRESULT. Como el FIFO RX del SIO solo guarda
 * 4 bytes, el host duerme 50ms (ver pc/protocol.py:send_tx_result) para
 * que tengamos tiempo de pintar la pantalla y entrar en el loop antes
 * de que llegue el primer byte. Aun asi, el primer byte cabe en FIFO. */
static void await_and_show_tx_result(void) {
    confirm_show_broadcasting();

    /* spinner cooperativo en (28, 10). Coords iguales que awaiting tx para
     * coherencia visual. */
    int spin_phase = 0;
    int spin_frame = 0;
    static const char spinner[] = "|/-\\";

    /* timeout total de 30s. El host normalmente responde en <2s, pero un
     * RPC lento (mainnet bajo carga) puede tardar mas. */
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

        if (input_pressed() & KEY_B) return;       /* user no quiere esperar */

        int b = uart_try_recv_byte();
        if (b < 0) {
            if (++frames > TIMEOUT_FRAMES) return; /* host no respondio */
            continue;
        }
        if (b != PROTO_TXRESULT) continue;          /* basura, ignora */
        got_opcode = 1;
        break;
    }
    if (!got_opcode) return;

    /* a partir de aqui esperamos el payload con timeout corto (1s) por byte
     * usando busy-spin para drenar el FIFO sin perder bytes. */
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
        /* status desconocido: muestra como error generico */
        const char* m = "unknown status from host";
        u32 mlen = 0;
        while (m[mlen]) mlen++;
        memcpy(errmsg, m, mlen);
        errlen = mlen;
        status = TXRESULT_BROADCAST_ERR;
    }

    confirm_show_tx_result(status, hash, errmsg, errlen);
}

static void sign_loop(void) {
    uart_init();
    render_ready_screen("READY");

    int spin_phase = 0;
    int spin_frame = 0;
    static const char spinner[] = "|/-\\";

    /* Loop principal cooperativo: cada VBlank actualiza UI, lanza un READY
     * cada N frames y hace peek no bloqueante por ACK. Asi el spinner se
     * mueve siempre y el usuario sabe que el firmware esta vivo. */
    const u32 READY_PULSE_FRAMES = 30;  /* 0.5s entre cada READY */
    u32 frames_since_ready = READY_PULSE_FRAMES;  /* fuerza envio inmediato */
    int saw_link_error = 0;

    for (;;) {
        VBlankIntrWait();
        input_poll();

        /* spinner cada 8 frames (~135ms) — mas visible que cada 16 */
        if ((++spin_frame & 7) == 0) {
            char s[2] = { spinner[(spin_phase++) & 3], 0 };
            text_at(28, 10, s);
        }

        if (input_pressed() & KEY_START) {
            wipe_secrets();
            text_clear();
            text_titlebar("GBA SIGNER", "LOCK");
            text_at(2, 6, "  >> session locked");
            text_at(2, 8, "  reset to start over");
            text_statusbar("---");
            for (;;) VBlankIntrWait();
        }

        /* Lanza un READY cada 0.5s. El host esta en perform_signing leyendo
         * 1 byte hasta el timeout, asi que pulsar en lugar de spamear ahorra
         * trafico y deja el FIFO TX limpio. */
        if (++frames_since_ready >= READY_PULSE_FRAMES) {
            protocol_send_ready();
            frames_since_ready = 0;
        }

        /* Peek no bloqueante: ha llegado ACK? */
        int b = uart_try_recv_byte();
        if (b < 0) continue;          /* nada aun, sigue al siguiente frame */
        if (b != PROTO_ACK) continue; /* basura, ignora y sigue */

        /* ACK recibido: pasamos al stream del payload (RLP). A partir de
         * aqui usamos las funciones bloqueantes del protocolo (busy-spin
         * para el FIFO, VBlank para esperas largas) hasta que la tx termine
         * y volvamos al ciclo de ready/ack. */
        u32 rlp_len = 0;
        if (!protocol_recv_tx_rlp(g_rlp_buf, sizeof(g_rlp_buf), &rlp_len)) {
            saw_link_error = 1;
            text_at(2, 13, "!! link/timeout error    ");
            continue;
        }
        if (saw_link_error) {
            /* limpia mensaje viejo si lo habia */
            text_at(2, 13, "                         ");
            saw_link_error = 0;
        }

        eth_tx tx;
        if (!eth_tx_decode(g_rlp_buf, rlp_len, &tx)) {
            /* RLP invalido o tipo no soportado */
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
            render_ready_screen("READY");
            continue;
        }

        int signed_ok = 0;
        if (confirm_tx(&tx)) {
            u8 hash[32];
            eth_tx_signing_hash(&tx, hash);
            u8 sig[65];
            if (eth_sign_hash(g_node.priv, hash, sig)) {
                protocol_send_sig(sig);
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

        /* Si firmamos, esperamos a que el host nos diga que tal le fue al
         * intentar broadcast (PROTO_TXRESULT). El usuario pulsa A para
         * volver a awaiting transaction o B para no esperar. Compatibilidad:
         * si el host es viejo y no envia TXRESULT, hacemos timeout
         * cooperativo y volvemos solo. */
        if (signed_ok) {
            await_and_show_tx_result();
        }

        render_ready_screen("READY");
    }
}

void wallet_run(void) {
    /* importante: input_init primero -> habilita IRQs y handler de VBlank
     * que necesita VBlankIntrWait dentro del banner. */
    input_init();
    text_init();
    uecc_register_rng();

    text_boot_banner();

    for (;;) {
        text_clear();
        text_titlebar("GBA SIGNER", "BOOT");
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
