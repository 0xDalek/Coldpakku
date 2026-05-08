#include "confirm.h"
#include "text.h"
#include "input.h"
#include "../types.h"
#include "../crypto/ethereum.h"
#include "../crypto/eth_tx.h"

#include <gba_input.h>
#include <gba_systemcalls.h>
#include <stdio.h>
#include <string.h>

/* IMPORTANTE: snprintf de newlib en devkitARM NO soporta %llu/%lld por
 * defecto (deshabilitado para reducir tamaño binario). Si lo usamos, el
 * texto sale truncado o basura. Por eso convertimos los u64 a decimal
 * con un helper manual y luego los inyectamos como %s. */

static int u64_to_str(u64 v, char* out, u32 outlen) {
    if (outlen == 0) return 0;
    if (v == 0) {
        if (outlen < 2) { out[0] = '\0'; return 0; }
        out[0] = '0'; out[1] = '\0';
        return 1;
    }
    char tmp[24];
    int n = 0;
    while (v) {
        tmp[n++] = (char)('0' + (v % 10));
        v /= 10;
    }
    int written = 0;
    while (n-- > 0 && (u32)(written + 1) < outlen) {
        out[written++] = tmp[n];
    }
    out[written] = '\0';
    return written;
}

/* Igual que u64_to_str pero rellenado a la izquierda con ceros hasta
 * `min_digits`. Útil para la parte decimal: 5 -> "000005" si min=6. */
static int u64_to_str_pad(u64 v, u32 min_digits, char* out, u32 outlen) {
    char tmp[24];
    int n = 0;
    if (v == 0) {
        tmp[n++] = '0';
    } else {
        while (v) {
            tmp[n++] = (char)('0' + (v % 10));
            v /= 10;
        }
    }
    while ((u32)n < min_digits && n < (int)sizeof(tmp)) {
        tmp[n++] = '0';
    }
    int written = 0;
    while (n-- > 0 && (u32)(written + 1) < outlen) {
        out[written++] = tmp[n];
    }
    out[written] = '\0';
    return written;
}

/* Formatea un value uint256 (big-endian) como "X.YYYYYY ETH" si cabe en u64,
 * o "(>2^64 wei)" en caso contrario. */
static int format_value_eth(const u8 value_be[32], char* out, u32 outlen) {
    for (int i = 0; i < 24; i++) {
        if (value_be[i] != 0) {
            return snprintf(out, outlen, "(>2^64 wei)");
        }
    }
    u64 v = 0;
    for (int i = 24; i < 32; i++) v = (v << 8) | value_be[i];
    if (v == 0) {
        return snprintf(out, outlen, "0 ETH");
    }
    u64 whole = v / 1000000000000000000ULL;
    u64 frac6 = (v / 1000000000000ULL) % 1000000ULL;
    char w[24], f[8];
    u64_to_str(whole, w, sizeof(w));
    u64_to_str_pad(frac6, 6, f, sizeof(f));
    return snprintf(out, outlen, "%s.%s ETH", w, f);
}

/* Formatea gas price (wei) como gwei. 1500000000 wei = "1.500 gwei". */
static int format_gwei(u64 wei, char* out, u32 outlen) {
    u64 gwei_int  = wei / 1000000000ULL;
    u64 gwei_frac = (wei / 1000000ULL) % 1000ULL;
    char i[24], f[8];
    u64_to_str(gwei_int, i, sizeof(i));
    u64_to_str_pad(gwei_frac, 3, f, sizeof(f));
    return snprintf(out, outlen, "%s.%s gwei", i, f);
}

/* === Páginas de la confirmación ===
 * Página 0: header (chainId, nonce, gas) + to + value
 * Página 1+: hex dump del data (24 bytes/fila, 8 filas/página = 192 b/página)
 */
#define DATA_BYTES_PER_LINE  10
#define DATA_LINES_PER_PAGE  8
#define DATA_BYTES_PER_PAGE  (DATA_BYTES_PER_LINE * DATA_LINES_PER_PAGE)

static u32 data_total_pages(u32 data_len) {
    if (data_len == 0) return 0;
    return (data_len + DATA_BYTES_PER_PAGE - 1) / DATA_BYTES_PER_PAGE;
}

static void render_page0(const eth_tx* tx) {
    char buf[64];
    char addr[43];

    text_clear();
    text_titlebar("CONFIRM TX", "WAIT");

    char num[24];
    u64_to_str(tx->chainid, num, sizeof(num));
    snprintf(buf, sizeof(buf), "  type: %s   chainId %s",
             tx->type == ETH_TX_TYPE_1559 ? "EIP-1559" : "legacy", num);
    text_at(0, 3, buf);

    u64_to_str(tx->nonce, num, sizeof(num));
    snprintf(buf, sizeof(buf), "  nonce: %s", num);
    text_at(0, 4, buf);

    if (tx->type == ETH_TX_TYPE_1559) {
        char fee[32];
        format_gwei(tx->max_fee_per_gas, fee, sizeof(fee));
        snprintf(buf, sizeof(buf), "  maxFee: %s", fee);
        text_at(0, 5, buf);
        format_gwei(tx->max_priority_fee_per_gas, fee, sizeof(fee));
        snprintf(buf, sizeof(buf), "  tip:    %s", fee);
        text_at(0, 6, buf);
    } else {
        char fee[32];
        format_gwei(tx->max_fee_per_gas, fee, sizeof(fee));
        snprintf(buf, sizeof(buf), "  gasPrice: %s", fee);
        text_at(0, 5, buf);
    }
    u64_to_str(tx->gas_limit, num, sizeof(num));
    snprintf(buf, sizeof(buf), "  gasLimit: %s", num);
    text_at(0, 7, buf);

    if (tx->has_to) {
        eth_address_to_eip55(tx->to, addr);
        text_at(0, 9, "  to:");
        /* address ocupa 42 chars, partimos en 2 lineas para que entre */
        text_printf_at(2, 10, "%.22s", addr);
        text_printf_at(2, 11, "%s", addr + 22);
    } else {
        text_at(0, 9, "  to: <CONTRACT CREATION>");
    }

    char val[40];
    format_value_eth(tx->value_be, val, sizeof(val));
    text_at(0, 13, "  value:");
    text_at(2, 14, val);

    snprintf(buf, sizeof(buf), "  data: %lu bytes",
             (unsigned long)tx->data_len);
    text_at(0, 16, buf);

    u32 npages = data_total_pages(tx->data_len);
    if (npages > 0) {
        text_statusbar("A sign  B cancel  R data >");
    } else {
        text_statusbar("A sign  B cancel");
    }
}

static void render_data_page(const eth_tx* tx, u32 page, u32 npages) {
    char buf[40];
    text_clear();
    text_titlebar("TX DATA", "HEX");

    snprintf(buf, sizeof(buf), "  page %lu / %lu",
             (unsigned long)(page + 1), (unsigned long)npages);
    text_at(0, 2, buf);

    u32 offset = page * DATA_BYTES_PER_PAGE;
    for (u32 line = 0; line < DATA_LINES_PER_PAGE; line++) {
        u32 line_off = offset + line * DATA_BYTES_PER_LINE;
        if (line_off >= tx->data_len) break;
        u32 take = DATA_BYTES_PER_LINE;
        if (line_off + take > tx->data_len) take = tx->data_len - line_off;

        snprintf(buf, sizeof(buf), "  %04lx:", (unsigned long)line_off);
        text_at(0, 4 + line, buf);
        text_hex(8, 4 + line, tx->data + line_off, take);
    }

    if (page + 1 < npages) {
        text_statusbar("A sign  B cancel  L< R> data");
    } else {
        text_statusbar("A sign  B cancel  L< page");
    }
}

int confirm_tx(const eth_tx* tx) {
    u32 npages    = data_total_pages(tx->data_len);
    u32 cur_page  = 0;        /* 0 = header, 1..npages = data pages */
    int dirty     = 1;

    /* parpadeo del asterisco "tx pendiente" */
    int blink = 1;
    int frame = 0;

    for (;;) {
        if (dirty) {
            if (cur_page == 0) {
                render_page0(tx);
            } else {
                render_data_page(tx, cur_page - 1, npages);
            }
            dirty = 0;
        }

        VBlankIntrWait();
        input_poll();

        if ((++frame & 31) == 0) {
            text_at(28, 0, blink ? "*" : " ");
            blink = !blink;
        }

        u16 k = input_pressed();
        if (!k) continue;

        if (k & KEY_A) return 1;
        if (k & KEY_B) return 0;
        if ((k & KEY_R) && cur_page < npages) { cur_page++; dirty = 1; }
        if ((k & KEY_L) && cur_page > 0)      { cur_page--; dirty = 1; }
    }
}

/* Espera a que el usuario suelte cualquier tecla. Llamar antes de salir
 * de una pantalla "A continue" evita que la pulsacion arrastre a la
 * siguiente. Defensivo: keysDown() ya hace edge detection, pero hardware
 * wallets clasicos lo hacen igual por robustez frente a key-repeat o
 * frames perdidos. */
static void wait_release(void) {
    for (;;) {
        VBlankIntrWait();
        input_poll();
        if (input_held() == 0) return;
    }
}

int confirm_yes_no(const char* prompt) {
    text_clear();
    text_titlebar("CONFIRM", "?");
    text_at(2, 6, prompt);
    text_at(2, 9, "  > A = yes");
    text_at(2, 10, "  > B = no");
    text_statusbar("A yes  B no");
    for (;;) {
        VBlankIntrWait();
        input_poll();
        u16 k = input_pressed();
        if (k & KEY_A) { wait_release(); return 1; }
        if (k & KEY_B) { wait_release(); return 0; }
    }
}

/* Pantalla de verificacion de address. La address se parte en 2 lineas
 * de 22 chars + el resto. Se enmarca en un cuadro ASCII y se destacan
 * los 4 primeros y 4 ultimos hex (lo que un humano compara de un vistazo
 * contra MetaMask). */
void confirm_show_address(const u8 address[20]) {
    text_clear();
    text_titlebar("ETH ADDRESS", "VERIFY");

    text_at(0, 3, "  account derivada:");

    char addr[43];
    eth_address_to_eip55(address, addr);   /* "0x" + 40 hex + NUL */

    /* marco ASCII para destacar la address */
    text_at(0, 5,  "  +----------------------+");
    char line[40];
    /* primera linea: 0x + 20 hex (= 22 chars) */
    snprintf(line, sizeof(line), "  | %.22s |", addr);
    text_at(0, 6, line);
    /* segunda linea: 20 hex restantes, padded a 22 */
    snprintf(line, sizeof(line), "  | %-22s |", addr + 22);
    text_at(0, 7, line);
    text_at(0, 8,  "  +----------------------+");

    /* resumen "primero...ultimo" para comparar de un vistazo */
    snprintf(line, sizeof(line), "  short: %.6s..%s", addr, addr + 38);
    text_at(0, 10, line);

    text_at(0, 12, "  Comparala con MetaMask:");
    text_at(0, 13, "    debe coincidir char a");
    text_at(0, 14, "    char (incl. mayusculas).");

    text_at(0, 16, "  >> A = continuar");
    text_at(0, 17, "  >> B = volver al inicio");

    text_statusbar("A continue  B cancel session");

    int blink = 1;
    int frame = 0;
    for (;;) {
        VBlankIntrWait();
        input_poll();
        u16 k = input_pressed();
        if (k & KEY_A) { wait_release(); return; }
        if (k & KEY_B) {
            /* Para "cancelar" hace falta que el caller lo detecte. Como
             * esta API no devuelve nada hoy, lo trato como "continuar"
             * tambien para no dejar al usuario atascado. El caller hara
             * confirm_yes_no("Guardar?") y ahi si puede decir no. */
            wait_release();
            return;
        }
        if ((++frame & 31) == 0) {
            text_at(28, 0, blink ? "*" : " ");
            blink = !blink;
        }
    }
}

/* Frame inicial de "BROADCASTING...". El sign_loop hace su propio loop
 * cooperativo encima animando el spinner en (28, 10) (las mismas coords
 * que awaiting transaction, para continuidad visual). */
void confirm_show_broadcasting(void) {
    text_clear();
    text_titlebar("TX BROADCAST", "WAIT");
    text_at(0, 3,  "  signature sent to host");
    text_at(0, 5,  "  awaiting RPC response");
    text_at(0, 7,  "  this can take 5-30s on");
    text_at(0, 8,  "  Sepolia mainnet typically");
    text_at(0, 10, "  status:                  ");
    text_at(0, 12, "  [B] dont wait, return now");
    text_statusbar("B skip wait");
}

/* Pantalla de resultado de la tx. status: ver confirm.h. Espera A. */
void confirm_show_tx_result(u8 status,
                            const u8 hash[32],
                            const char* errmsg, u32 errlen) {
    text_clear();

    const char* tag;
    const char* line0;
    switch (status) {
        case 0x00: tag = "SENT";    line0 = "  > broadcast accepted"; break;
        case 0x01: tag = "ERROR";   line0 = "  > broadcast REJECTED";  break;
        case 0x02: tag = "UNSENT";  line0 = "  > signed, NOT broadcast"; break;
        default:   tag = "RESULT";  line0 = "  > unknown status";       break;
    }
    text_titlebar("TX RESULT", tag);
    text_at(0, 3, line0);

    if (status == 0x00 || status == 0x02) {
        char hex[65];
        for (u32 i = 0; i < 32; i++) {
            static const char H[] = "0123456789abcdef";
            hex[i * 2 + 0] = H[(hash[i] >> 4) & 0xF];
            hex[i * 2 + 1] = H[ hash[i]       & 0xF];
        }
        hex[64] = '\0';

        text_at(0, 5, "  tx hash:");
        text_at(0, 6, "  +------------------------+");
        char line[40];
        /* dos lineas de 32 hex chars dentro del marco (32 + 2 padding bars)
         * pero la pantalla tiene 30 cols utiles, asi que partimos en 22+22+20. */
        snprintf(line, sizeof(line), "  | %.22s |", hex);
        text_at(0, 7, line);
        snprintf(line, sizeof(line), "  | %.22s |", hex + 22);
        text_at(0, 8, line);
        snprintf(line, sizeof(line), "  | %-22s |", hex + 44);
        text_at(0, 9, line);
        text_at(0, 10, "  +------------------------+");

        snprintf(line, sizeof(line), "  short: %.6s..%s", hex, hex + 60);
        text_at(0, 12, line);

        if (status == 0x00) {
            text_at(0, 14, "  verify on a block");
            text_at(0, 15, "  explorer (etherscan etc)");
        } else {
            text_at(0, 14, "  --no-broadcast: signed");
            text_at(0, 15, "  but NOT sent. Save raw");
            text_at(0, 16, "  tx from the host log.");
        }
    } else {
        /* error: muestra mensaje ASCII truncado */
        text_at(0, 5, "  RPC said:");
        text_at(0, 6, "  +------------------------+");
        char line[40];
        u32 lim = errlen < 22 ? errlen : 22;
        snprintf(line, sizeof(line), "  | %.*s%*s |",
                 (int)lim, errmsg ? errmsg : "(no msg)",
                 (int)(22 - lim), "");
        text_at(0, 7, line);
        if (errlen > 22) {
            u32 rem = errlen - 22;
            if (rem > 22) rem = 22;
            snprintf(line, sizeof(line), "  | %.*s%*s |",
                     (int)rem, errmsg + 22, (int)(22 - rem), "");
            text_at(0, 8, line);
        } else {
            text_at(0, 8, "  |                        |");
        }
        text_at(0, 9, "  +------------------------+");

        text_at(0, 12, "  the tx was NOT mined.");
        text_at(0, 13, "  fix the issue and retry.");
    }

    text_at(0, 18, "  >> A = back to awaiting");
    text_statusbar("A return to ready");

    /* limpia teclas pulsadas previas (la A de confirm_tx puede arrastrarse) */
    wait_release();
    for (;;) {
        VBlankIntrWait();
        input_poll();
        if (input_pressed() & KEY_A) { wait_release(); return; }
    }
}
