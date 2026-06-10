#include "confirm.h"
#include "text.h"
#include "input.h"
#include "chains.h"
#include "../types.h"
#include "../crypto/ethereum.h"
#include "../crypto/eth_tx.h"
#include "../crypto/eth_abi.h"
#include "../crypto/abi_decoder.h"
#include "../crypto/eip712.h"

#include <gba_input.h>
#include <gba_base.h>
#include <gba_systemcalls.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

/* IMPORTANT: snprintf in devkitARM's newlib does NOT support %llu/%lld
 * by default (disabled to reduce binary size). If we use them the
 * output ends up truncated or garbled. We convert u64 to decimal with
 * a manual helper and then inject as %s. */

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

/* Same as u64_to_str but left-padded with zeros up to `min_digits`.
 * Useful for the decimal part: 5 -> "000005" if min=6. */
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

/* Formats a uint256 (big-endian) value as "X.YYYYYY <SYMBOL>" if it
 * fits in u64, or "(>2^64 wei)" otherwise. `symbol` is the chain's
 * native symbol (ETH, POL, BNB, AVAX, MNT, xDAI, ...). */
static int format_value(const u8 value_be[32], const char* symbol,
                        char* out, u32 outlen) {
    for (int i = 0; i < 24; i++) {
        if (value_be[i] != 0) {
            return snprintf(out, outlen, "(>2^64 wei)");
        }
    }
    u64 v = 0;
    for (int i = 24; i < 32; i++) v = (v << 8) | value_be[i];
    if (v == 0) {
        return snprintf(out, outlen, "0 %s", symbol);
    }
    u64 whole = v / 1000000000000000000ULL;
    u64 frac6 = (v / 1000000000000ULL) % 1000000ULL;
    char w[24], f[8];
    u64_to_str(whole, w, sizeof(w));
    u64_to_str_pad(frac6, 6, f, sizeof(f));
    return snprintf(out, outlen, "%s.%s %s", w, f, symbol);
}

/* Formats gas price (wei) as gwei. 1500000000 wei = "1.500 gwei". */
static int format_gwei(u64 wei, char* out, u32 outlen) {
    u64 gwei_int  = wei / 1000000000ULL;
    u64 gwei_frac = (wei / 1000000ULL) % 1000ULL;
    char i[24], f[8];
    u64_to_str(gwei_int, i, sizeof(i));
    u64_to_str_pad(gwei_frac, 3, f, sizeof(f));
    return snprintf(out, outlen, "%s.%s gwei", i, f);
}

/* 10^e as u64. Valid only for e <= 19 (10^20 overflows u64). */
static u64 pow10_u64(u8 e) {
    u64 r = 1;
    while (e--) r *= 10ULL;
    return r;
}

/* Formats a uint256 with arbitrary decimals + symbol. Same as
 * format_value but the divisor is chosen by `decimals` instead of
 * hard-coding 18. Shows at most 6 fractional digits (enough for UX);
 * for tokens with fewer decimals (USDC=6, WBTC=8) it shows them all.
 * If the value does not fit in u64, falls back to raw. */
static int format_amount_with_decimals(const u8 value_be[32], u8 decimals,
                                       const char* symbol,
                                       char* out, u32 outlen) {
    for (int i = 0; i < 24; i++) {
        if (value_be[i] != 0) {
            return snprintf(out, outlen, "(>2^64 raw)");
        }
    }
    u64 v = 0;
    for (int i = 24; i < 32; i++) v = (v << 8) | value_be[i];

    char w[24];
    if (v == 0) {
        return snprintf(out, outlen, "0 %s", symbol);
    }
    if (decimals == 0) {
        u64_to_str(v, w, sizeof(w));
        return snprintf(out, outlen, "%s %s", w, symbol);
    }
    if (decimals > 19) {
        u64_to_str(v, w, sizeof(w));
        return snprintf(out, outlen, "%s raw (dec=%u)", w, decimals);
    }
    u64 unit  = pow10_u64(decimals);
    u64 whole = v / unit;
    u8  disp  = decimals < 6 ? decimals : 6;
    u64 frac_full = v % unit;
    u64 frac_disp = (decimals > disp)
                    ? frac_full / pow10_u64(decimals - disp)
                    : frac_full;
    char f[8];
    u64_to_str(whole, w, sizeof(w));
    u64_to_str_pad(frac_disp, disp, f, sizeof(f));
    return snprintf(out, outlen, "%s.%s %s", w, f, symbol);
}

/* Formats a uint256 BE as a readable string:
 *   - If it fits in u64 (high 24 bytes == 0): full decimal, e.g.
 *     "1000000000000000000".
 *   - Otherwise, truncated hex "0xAaBbCcDd..EeFf0011" (8 nibbles each
 *     side).
 * outlen >= 24 recommended. Returns chars written. */
static int format_uint256(const u8 v[32], char* out, u32 outlen) {
    int fits_u64 = 1;
    for (u32 i = 0; i < 24; i++) {
        if (v[i] != 0) { fits_u64 = 0; break; }
    }
    if (fits_u64) {
        u64 n = 0;
        for (u32 i = 24; i < 32; i++) n = (n << 8) | v[i];
        return u64_to_str(n, out, outlen);
    }
    static const char H[] = "0123456789abcdef";
    if (outlen < 21) {
        if (outlen > 0) out[0] = '\0';
        return 0;
    }
    out[0] = '0'; out[1] = 'x';
    /* first 4 bytes -> 8 nibbles */
    for (u32 i = 0; i < 4; i++) {
        out[2 + i*2 + 0] = H[(v[i] >> 4) & 0xF];
        out[2 + i*2 + 1] = H[ v[i]       & 0xF];
    }
    out[10] = '.'; out[11] = '.';
    /* last 4 bytes -> 8 nibbles */
    for (u32 i = 0; i < 4; i++) {
        u8 b = v[28 + i];
        out[12 + i*2 + 0] = H[(b >> 4) & 0xF];
        out[12 + i*2 + 1] = H[ b       & 0xF];
    }
    out[20] = '\0';
    return 20;
}

/* === Confirmation pages ===
 * Page 0: header (chainId, nonce, gas) + to + value
 * Page 1+: hex dump of the data (24 bytes/row, 8 rows/page = 192 b/page)
 */
#define DATA_BYTES_PER_LINE  10
#define DATA_LINES_PER_PAGE  8
#define DATA_BYTES_PER_PAGE  (DATA_BYTES_PER_LINE * DATA_LINES_PER_PAGE)

static u32 data_total_pages(u32 data_len) {
    if (data_len == 0) return 0;
    return (data_len + DATA_BYTES_PER_PAGE - 1) / DATA_BYTES_PER_PAGE;
}

/* One-line summary for the "data:" row of page 0. Reflects is_infinite
 * / approved_bool with (!) so the risk is visible without having to
 * navigate to the decoded page. */
static const char* abi_summary(const eth_abi_call* abi) {
    switch (abi->kind) {
    case ETH_ABI_ERC20_TRANSFER:
        return "ERC-20 transfer";
    case ETH_ABI_ERC20_APPROVE:
        return abi->is_infinite ? "approve INFINITE (!)"
                                : "ERC-20 approve";
    case ETH_ABI_TRANSFER_FROM:
        return "transferFrom";
    case ETH_ABI_SAFE_TRANSFER_FROM:
        return "ERC-721 transfer";
    case ETH_ABI_SET_APPROVAL_FOR_ALL:
        return abi->approved_bool ? "approve ALL NFTS (!)"
                                  : "revoke NFT approval";
    case ETH_ABI_WETH_DEPOSIT:
        return "wrap (deposit)";
    case ETH_ABI_WETH_WITHDRAW:
        return "unwrap (withdraw)";
    default:
        return "";
    }
}

/* === DECODED page for WRAP / UNWRAP ====================================
 * Special variant for deposit() / withdraw(uint256) when the `to`
 * contract matches the known wrapped-native of the active chain (WETH
 * on Ethereum, WBNB on BSC, WMATIC on Polygon...). Symmetric render:
 *
 *   - 1.500000 BNB
 *   + 1.500000 WBNB
 *
 * If `to` doesn't match the expected wrapper, we fall back to a generic
 * render with a warning ("this contract is not the known wrapper")
 * — it could be a staking or another contract that reuses the selector.
 * ======================================================================= */
static void render_wrap_unwrap_page(const eth_tx* tx,
                                    const chain_info* ci,
                                    const eth_abi_call* abi,
                                    const tx_meta* meta,
                                    u32 extra_pages_after) {
    /* buf=48 leaves headroom over val=40 + the prefix "    - " (6 chars);
     * avoids -Wformat-truncation warnings even though snprintf truncates
     * safely. */
    char buf[48];
    char addr[43];
    char val[40];

    int is_deposit = (abi->kind == ETH_ABI_WETH_DEPOSIT);
    /* We enable the pretty view "-X NATIVE -> +X WSYMBOL" only if the
     * host gave us a symbol for the to: contract (extension queries
     * `symbol()` via RPC). Without meta, the GBA does not assume
     * anything and shows a generic render with the `to:` and the raw
     * amount. */
    int is_wrapper = (tx->has_to && meta && meta->has_to_symbol);

    const char* status = is_wrapper ? (is_deposit ? "WRAP" : "UNWRAP")
                                    : "DECODED";
    text_titlebar("TX DATA", status);

    text_at(0, 2, "  function:");
    text_at(0, 3, is_deposit ? "    deposit()  -- wrap"
                             : "    withdraw(amount)");

    u32 row = 5;

    if (is_wrapper) {
        const char* native_sym  = ci->native_sym;
        const char* wrapped_sym = meta->to_symbol;

        /* For deposit the amount comes in tx.value; for withdraw in data. */
        const u8* amount_be = is_deposit ? tx->value_be : abi->value_be;

        const char* minus_sym = is_deposit ? native_sym  : wrapped_sym;
        const char* plus_sym  = is_deposit ? wrapped_sym : native_sym;

        format_value(amount_be, minus_sym, val, sizeof(val));
        snprintf(buf, sizeof(buf), "    - %s", val);
        text_at(0, row++, buf);

        format_value(amount_be, plus_sym, val, sizeof(val));
        snprintf(buf, sizeof(buf), "    + %s", val);
        text_at(0, row++, buf);
        row++;

        snprintf(buf, sizeof(buf), "  contract (%s):", wrapped_sym);
        text_at(0, row++, buf);
        eth_address_to_eip55(tx->to, addr);
        text_printf_at(2, row++, "%.22s", addr);
        text_printf_at(2, row++, "%s", addr + 22);
        row++;

        text_at(0, row++, is_deposit ? "  amount = tx.value"
                                     : "  amount = data arg");
    } else {
        /* The host did not give us a symbol for the to: contract. We
         * show a generic render without assuming this is a real wrap
         * (it could be staking or another contract reusing the
         * selector). */
        text_at(0, row++, "  (no token info from");
        text_at(0, row++, "   host for this to:)");
        row++;
        if (is_deposit) {
            text_at(0, row++, "  amount (tx.value):");
            format_value(tx->value_be, ci->native_sym, val, sizeof(val));
            snprintf(buf, sizeof(buf), "    %s", val);
            text_at(0, row++, buf);
        } else {
            text_at(0, row++, "  amount (raw uint256):");
            char vbuf[28];
            format_uint256(abi->value_be, vbuf, sizeof(vbuf));
            snprintf(buf, sizeof(buf), "    %s", vbuf);
            text_at(0, row++, buf);
            text_at(0, row++, "  (decimals unknown)");
        }
    }

    if (extra_pages_after > 0) {
        text_statusbar("A sign  B cancel  L< R> hex");
    } else {
        text_statusbar("A sign  B cancel  L< page");
    }
}

/* === DECODED page =======================================================
 * Appears between page 0 (header) and the hex pages when we recognise a
 * known ABI selector. Shows function, involved addresses and value/bool,
 * with a warning box for drainer-grade cases (infinite approve,
 * setApprovalForAll(true)).
 *
 * If the token's decimals were known we could format as "1.500000 USDC"
 * but in Phase A we don't have a token registry, so we display the raw
 * uint256 (decimal if it fits in u64, truncated hex otherwise).
 * ======================================================================= */
static void render_decoded_page(const eth_tx* tx,
                                const chain_info* ci,
                                const eth_abi_call* abi,
                                const tx_meta* meta,
                                u32 extra_pages_after) {
    /* WRAP/UNWRAP have their own layout (symmetric render). Delegate. */
    if (abi->kind == ETH_ABI_WETH_DEPOSIT
        || abi->kind == ETH_ABI_WETH_WITHDRAW) {
        render_wrap_unwrap_page(tx, ci, abi, meta, extra_pages_after);
        return;
    }
    /* buf=48 leaves headroom over val=40 + the prefix "    %s" (4 chars);
     * avoids -Wformat-truncation warnings even though snprintf truncates
     * safely. */
    char buf[48];
    char addr[43];

    text_clear();

    /* titlebar with sub-status to visually reinforce the dangerous case */
    const char* status = "DECODED";
    int has_warning = 0;
    if (abi->kind == ETH_ABI_ERC20_APPROVE && abi->is_infinite) {
        status = "INFINITE!";
        has_warning = 1;
    } else if (abi->kind == ETH_ABI_SET_APPROVAL_FOR_ALL && abi->approved_bool) {
        status = "ALL NFTS";
        has_warning = 1;
    }
    text_titlebar("TX DATA", status);

    /* Function + address labels, all together in a single switch so we
     * don't rewrite the switch three times. */
    const char* fname    = "";
    const char* label_a  = "";
    const char* label_b  = NULL;
    switch (abi->kind) {
    case ETH_ABI_ERC20_TRANSFER:
        fname = "transfer  (ERC-20)";  label_a = "  recipient:";        break;
    case ETH_ABI_ERC20_APPROVE:
        fname = "approve   (ERC-20)";  label_a = "  spender:";          break;
    case ETH_ABI_TRANSFER_FROM:
        fname = "transferFrom";        label_a = "  from:";  label_b = "  to:"; break;
    case ETH_ABI_SAFE_TRANSFER_FROM:
        fname = "safeTransferFrom";    label_a = "  from:";  label_b = "  to:"; break;
    case ETH_ABI_SET_APPROVAL_FOR_ALL:
        fname = "setApprovalForAll";   label_a = "  operator:";          break;
    default:
        /* should not happen: confirm_tx only enters here if kind != UNKNOWN */
        return;
    }

    text_at(0, 2, "  function:");
    snprintf(buf, sizeof(buf), "    %s", fname);
    text_at(0, 3, buf);

    u32 row = 5;

    if (has_warning) {
        text_at(0, row,     "  +----------------------+");
        text_at(0, row + 1, (abi->kind == ETH_ABI_ERC20_APPROVE)
                              ? "  |  INFINITE APPROVAL!  |"
                              : "  |  ALL NFTS APPROVED!  |");
        text_at(0, row + 2, "  +----------------------+");
        row += 4;
    }

    /* addr A (always) */
    text_at(0, row++, label_a);
    eth_address_to_eip55(abi->addr_a, addr);
    text_printf_at(2, row++, "%.22s", addr);
    text_printf_at(2, row++, "%s", addr + 22);
    row++;  /* blank */

    /* addr B (transferFrom / safeTransferFrom) */
    if (label_b && abi->has_addr_b) {
        text_at(0, row++, label_b);
        eth_address_to_eip55(abi->addr_b, addr);
        text_printf_at(2, row++, "%.22s", addr);
        text_printf_at(2, row++, "%s", addr + 22);
        row++;
    }

    /* Helper: if the host gave us symbol+decimals of the to: token
     * (ERC-20), we display "1.500000 USDC" instead of "1500000 raw". */
    int host_token_info = (meta && meta->has_to_symbol && meta->has_to_decimals);

    /* value (or bool) */
    switch (abi->kind) {
    case ETH_ABI_ERC20_TRANSFER:
    case ETH_ABI_ERC20_APPROVE: {
        if (abi->is_infinite) {
            text_at(0, row++, "  amount:");
            text_at(0, row++, "    2^256 - 1 (UNLIMITED)");
        } else if (host_token_info) {
            char val[40];
            format_amount_with_decimals(abi->value_be, meta->to_decimals,
                                        meta->to_symbol, val, sizeof(val));
            text_at(0, row++, "  amount (host says):");
            snprintf(buf, sizeof(buf), "    %s", val);
            text_at(0, row++, buf);
        } else {
            char val[28];
            format_uint256(abi->value_be, val, sizeof(val));
            text_at(0, row++, "  amount (raw uint256):");
            snprintf(buf, sizeof(buf), "    %s", val);
            text_at(0, row++, buf);
            text_at(0, row++, "  (decimals unknown)");
        }
        break;
    }
    case ETH_ABI_TRANSFER_FROM: {
        if (host_token_info) {
            char val[40];
            format_amount_with_decimals(abi->value_be, meta->to_decimals,
                                        meta->to_symbol, val, sizeof(val));
            text_at(0, row++, "  amount (host says):");
            snprintf(buf, sizeof(buf), "    %s", val);
            text_at(0, row++, buf);
            text_at(0, row++, "  (or NFT tokenId; verify)");
        } else {
            char val[28];
            format_uint256(abi->value_be, val, sizeof(val));
            text_at(0, row++, "  amount / tokenId:");
            snprintf(buf, sizeof(buf), "    %s", val);
            text_at(0, row++, buf);
            text_at(0, row++, "  (ERC-20 amt or NFT id)");
        }
        break;
    }
    case ETH_ABI_SAFE_TRANSFER_FROM: {
        text_at(0, row++, "  tokenId:");
        char val[28];
        format_uint256(abi->value_be, val, sizeof(val));
        snprintf(buf, sizeof(buf), "    %s", val);
        text_at(0, row++, buf);
        break;
    }
    case ETH_ABI_SET_APPROVAL_FOR_ALL: {
        snprintf(buf, sizeof(buf), "  approved: %s",
                 abi->approved_bool ? "TRUE  (grant)" : "FALSE (revoke)");
        text_at(0, row++, buf);
        if (abi->approved_bool) {
            row++;
            text_at(0, row++, "  grants operator FULL");
            text_at(0, row++, "  control of all NFTs in");
            text_at(0, row++, "  this collection.");
        } else {
            text_at(0, row++, "  removes prior approval.");
        }
        break;
    }
    default:
        break;
    }

    if (extra_pages_after > 0) {
        text_statusbar("A sign  B cancel  L< R> hex");
    } else {
        text_statusbar("A sign  B cancel  L< page");
    }
}

static void render_page0(const eth_tx* tx, const chain_info* ci,
                         const u8 signing_hash[32],
                         const eth_abi_call* abi,
                         const abi_decoded_t* decoded_v3,
                         const tx_meta* meta,
                         u32 extra_pages) {
    char buf[64];
    char addr[43];

    text_clear();
    text_titlebar("CONFIRM TX", "WAIT");

    /* === Network header ===================================================
     * Row 2: "<ABBR> <network name>"  with the chain icon at the
     * upper-right corner (sprite, OBJ layer). The icon is drawn from
     * confirm_tx once before the loop, so here we only write text.
     * Row 3: "type EIP-1559   chainId 1"
     * ====================================================================== */
    char num[24];
    snprintf(buf, sizeof(buf), "  %-4s %s", ci->abbr, ci->name);
    text_at(0, 2, buf);

    u64_to_str(tx->chainid, num, sizeof(num));
    snprintf(buf, sizeof(buf), "  %-8s   chainId %s",
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

    /* origin: hint from the host about which dApp is asking to sign.
     * NOT verifiable by the GBA — the host can lie — but invaluable
     * against phishing dApps that impersonate others. Truncated to 20
     * chars to fit the column without scrolling. */
    if (meta && meta->has_origin) {
        snprintf(buf, sizeof(buf), "  origin: %.20s", meta->origin);
        text_at(0, 8, buf);
    }

    if (tx->has_to) {
        eth_address_to_eip55(tx->to, addr);
        text_at(0, 9, "  to:");
        /* the address is 42 chars; we split into 2 lines to fit */
        text_printf_at(2, 10, "%.22s", addr);
        text_printf_at(2, 11, "%s", addr + 22);
        /* host's label for the contract (e.g. "WETH9", "Uniswap V3
         * Router"). Same trust model as origin: informative, not
         * crypto-verifiable. */
        if (meta && meta->has_to_name) {
            snprintf(buf, sizeof(buf), "    (%.20s)", meta->to_name);
            text_at(0, 12, buf);
        }
    } else {
        text_at(0, 9, "  to: <CONTRACT CREATION>");
    }

    /* `value:` with the chain's native symbol (ETH, POL, BNB, AVAX, MNT, xDAI). */
    char val[40];
    format_value(tx->value_be, ci->native_sym, val, sizeof(val));
    text_at(0, 13, "  value:");
    text_at(2, 14, val);

    /* If we recognise a known selector we highlight it here; the detail
     * shows up with R on the DECODED page. If is_infinite or
     * approveAll, the "(!)" in abi_summary() already warns the user on
     * page 0. */
    /* === data: line + trust badge ==========================================
     * Most important UX bit on this page: the user MUST be able to tell
     * "the cartridge understands this calldata" from "the cartridge does
     * NOT understand it and I'm trusting the browser/dApp". Whenever
     * there is any calldata at all, row 17 carries a single-line badge
     * that's visually impossible to confuse with the other one:
     *
     *   [+ PARSED on-device +]    <- cartridge decoded the args
     *   [+ DECODED on-device +]   <- legacy v0.2 decoder hit
     *   [!! BLIND SIGN !!]        <- nobody decoded; raw hex only
     *
     * Tx without calldata (plain ETH transfer) shows nothing extra:
     * there is nothing to decode in the first place. */
    if (abi && abi->kind != ETH_ABI_UNKNOWN) {
        snprintf(buf, sizeof(buf), "  data: %s", abi_summary(abi));
        text_at(0, 16, buf);
        text_at(0, 17, "  [+ DECODED on-device +]");
    } else if (decoded_v3 && decoded_v3->fn) {
        snprintf(buf, sizeof(buf), "  data: %.18s%s",
                 decoded_v3->fn->func_name,
                 (decoded_v3->fn->flags & ABI_FN_FLAG_DRAINER) ? " (!)" : "");
        text_at(0, 16, buf);
        text_at(0, 17, "  [+ PARSED on-device +]");
    } else if (tx->data_len > 0) {
        snprintf(buf, sizeof(buf), "  data: %lu bytes",
                 (unsigned long)tx->data_len);
        text_at(0, 16, buf);
        text_at(0, 17, "  [!! BLIND SIGN !!]");
    } else {
        text_at(0, 16, "  data: (none)");
    }

    /* === TX ID =============================================================
     * First 4 bytes (8 hex chars) of the signing hash. The PC extension
     * shows exactly the same value in its popup as "TX ID". If both IDs
     * do not match, there is tampering in between: DO NOT sign.
     * We highlight it in an ASCII box between the data and the statusbar.
     * ====================================================================== */
    if (signing_hash) {
        snprintf(buf, sizeof(buf),
                 "  ID: 0x%02x%02x%02x%02x  (chk PC)",
                 signing_hash[0], signing_hash[1],
                 signing_hash[2], signing_hash[3]);
        text_at(0, 18, buf);
    }

    if (extra_pages > 0) {
        const char* hint;
        if (abi && abi->kind != ETH_ABI_UNKNOWN) {
            hint = "A sign  B cancel  R decoded >";
        } else if (decoded_v3 && decoded_v3->fn) {
            hint = "A sign  B cancel  R parsed >";
        } else {
            /* Blind: name the hex view as such in the hint, so the
             * user doesn't think "R data >" is just an extra detail
             * page. Matches the [!! BLIND SIGN !!] badge above. */
            hint = "A sign  B cancel  R BLIND hex >";
        }
        text_statusbar(hint);
    } else {
        text_statusbar("A sign  B cancel");
    }
}

/* The hex view of the calldata serves two purposes that the user MUST
 * be able to tell apart:
 *
 *   - is_blind=1: the cartridge did NOT recognise the selector. This
 *     view is the ONLY thing the user has, and pressing A here means
 *     trusting the host about what these bytes do. Titlebar says
 *     "BLIND!" and the page counter is suffixed "(blind)" so the
 *     mode is clear on every page. The page 0 of the header already
 *     showed the full BLIND SIGN badge.
 *
 *   - is_blind=0: the cartridge DID decode the calldata; this hex
 *     page is just an audit-only secondary view reached via L+R from
 *     the parsed page. Titlebar "RAW HEX" + "(audit)" suffix so the
 *     user does not mistake it for the primary source of truth.
 */
static void render_data_page(const eth_tx* tx, u32 page, u32 npages,
                             int is_blind) {
    char buf[40];
    text_clear();
    text_titlebar("TX DATA", is_blind ? "BLIND!" : "RAW HEX");

    snprintf(buf, sizeof(buf), "  page %lu / %lu  %s",
             (unsigned long)(page + 1), (unsigned long)npages,
             is_blind ? "(blind sign)" : "(audit)");
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

/* =======================================================================
 * Generic "PARSED" page driven by abi_decoder.c. Used as a fallback for
 * selectors that the legacy eth_abi_decode() does NOT cover (v0.3): all
 * the Uniswap V2 router fns, ERC-2612 permit, multicall, Universal Router
 * execute, etc. Layout is intentionally flat-indented (same UX as the
 * EIP-712 parsed view shipped in v0.2) so the user does not have to learn
 * a new pattern per function.
 * ======================================================================= */

/* Significant byte count per uintN/intN type. Used to detect "all ones"
 * (rendered as "MAX (infinite)") and to size the displayed value. Entries
 * left zero are non-uint types: format_abi_uint() will refuse them. */
static const u8 ABI_T_NBYTES[] = {
    [ABI_T_UINT8]            = 1,
    [ABI_T_UINT16]           = 2,
    [ABI_T_UINT24]           = 3,
    [ABI_T_UINT32]           = 4,
    [ABI_T_UINT48]           = 6,
    [ABI_T_UINT64]           = 8,
    [ABI_T_UINT128]          = 16,
    [ABI_T_UINT160]          = 20,
    [ABI_T_UINT256]          = 32,
    [ABI_T_INT256]           = 32,
    [ABI_T_DEADLINE_UINT256] = 32,
};

static void format_abi_uint(const u8 raw[32], abi_type_t type,
                            char* out, u32 cap) {
    if ((u32)type >= sizeof(ABI_T_NBYTES) || ABI_T_NBYTES[type] == 0) {
        snprintf(out, cap, "?");
        return;
    }
    u8 nb = ABI_T_NBYTES[type];
    /* "Infinite approval" detection: any uint of >= 128 bits whose
     * meaningful bytes are all 0xFF. Mirrors the same heuristic the
     * EIP-712 parser uses for Permit2's uint160 amount. */
    if (nb >= 16) {
        int all_ones = 1;
        for (u32 i = 32 - nb; i < 32; i++) {
            if (raw[i] != 0xff) { all_ones = 0; break; }
        }
        if (all_ones) { snprintf(out, cap, "MAX (infinite)"); return; }
    }
    format_uint256(raw, out, cap);
}

/* Renders one decoded argument starting at `row`. Returns the next free
 * row. Bounded to row <= 18 by the caller. */
static u32 render_one_arg(u32 row, const abi_decoded_arg_t* a,
                          const char* name) {
    char buf[40];

    /* Label line. Long names won't wrap; they're truncated in the
     * format string. */
    snprintf(buf, sizeof(buf), "  %.20s:", name);
    text_at(0, row++, buf);

    switch (a->type) {
        case ABI_T_ADDRESS: {
            char addr[43];
            eth_address_to_eip55(&a->v.raw[12], addr);
            text_printf_at(2, row++, "%.22s", addr);
            text_printf_at(2, row++, "%s", addr + 22);
            break;
        }
        case ABI_T_BOOL: {
            text_printf_at(4, row++, "%s",
                           a->v.raw[31] ? "true (grant)" : "false (revoke)");
            break;
        }
        case ABI_T_UINT8: case ABI_T_UINT16: case ABI_T_UINT24:
        case ABI_T_UINT32: case ABI_T_UINT48: case ABI_T_UINT64:
        case ABI_T_UINT128: case ABI_T_UINT160: case ABI_T_UINT256:
        case ABI_T_INT256:
        case ABI_T_DEADLINE_UINT256: {
            char val[28];
            format_abi_uint(a->v.raw, a->type, val, sizeof(val));
            text_printf_at(4, row++, "%s", val);
            if (a->type == ABI_T_DEADLINE_UINT256) {
                /* GBA has no RTC; we cannot render "in X mins" without
                 * trusting the host. Just label the meaning. */
                text_at(4, row++, "(unix timestamp)");
            }
            break;
        }
        case ABI_T_BYTES4: {
            text_printf_at(4, row++, "0x%02x%02x%02x%02x",
                           a->v.raw[0], a->v.raw[1], a->v.raw[2], a->v.raw[3]);
            break;
        }
        case ABI_T_BYTES32: {
            /* 32 bytes = 64 hex chars; split as 22+22+20 to fit 30-col rows
             * (with 4 leading spaces of indent). */
            text_printf_at(4, row++,
                           "0x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                           a->v.raw[0], a->v.raw[1], a->v.raw[2],
                           a->v.raw[3], a->v.raw[4], a->v.raw[5],
                           a->v.raw[6], a->v.raw[7], a->v.raw[8]);
            text_printf_at(4, row++,
                           "%02x%02x%02x..%02x%02x%02x%02x",
                           a->v.raw[9],  a->v.raw[10], a->v.raw[11],
                           a->v.raw[28], a->v.raw[29], a->v.raw[30], a->v.raw[31]);
            break;
        }
        case ABI_T_BYTES:
        case ABI_T_STRING: {
            text_printf_at(4, row++, "%u bytes", (unsigned)a->v.dyn.count);
            break;
        }
        case ABI_T_BYTES_SUB_COUNT: {
            text_printf_at(4, row++, "%u bytes (sub-cmd)",
                           (unsigned)a->v.dyn.count);
            break;
        }
        case ABI_T_BYTES_ARRAY_SUB_COUNT: {
            text_printf_at(4, row++, "%u sub-cmd%s",
                           (unsigned)a->v.dyn.count,
                           a->v.dyn.count == 1 ? "" : "s");
            break;
        }
        case ABI_T_ADDRESS_ARRAY: {
            text_printf_at(4, row++, "%u hop%s",
                           (unsigned)a->v.dyn.count,
                           a->v.dyn.count == 1 ? "" : "s");
            /* Up to 3 hops fit comfortably; beyond that we hint "(+)". */
            u32 nshow = a->v.dyn.count > 3 ? 3 : a->v.dyn.count;
            for (u32 j = 0; j < nshow && row < 18; j++) {
                const u8* p = a->v.dyn.ptr + j * 32 + 12;
                text_printf_at(4, row++,
                               "[%u] 0x%02x%02x%02x..%02x%02x",
                               (unsigned)j, p[0], p[1], p[2], p[18], p[19]);
            }
            if (a->v.dyn.count > nshow && row < 18) {
                text_at(4, row++, "(+more)");
            }
            break;
        }
        default:
            text_at(4, row++, "(unsupported type)");
            break;
    }
    return row;
}

static void render_parsed_page(const eth_tx* tx,
                               const chain_info* ci,
                               const abi_decoded_t* d,
                               const tx_meta* meta,
                               u32 extra_pages_after) {
    (void)tx; (void)ci; (void)meta;

    text_clear();
    /* Titlebar sub-status is always "PARSED" so it lines up visually
     * with "DECODED" (legacy pretty page) and "BLIND!" (hex when
     * the cartridge could NOT decode). The function name moves into
     * the body where there's room. */
    text_titlebar("TX DATA", "PARSED");

    u32 row = 2;
    char buf[40];
    snprintf(buf, sizeof(buf), "  function: %.18s",
             d->fn->func_name);
    text_at(0, row++, buf);
    row++;  /* blank */

    if (d->fn->flags & ABI_FN_FLAG_DRAINER) {
        /* Same visual treatment as the legacy "INFINITE APPROVAL" /
         * "ALL NFTS APPROVED" boxes — boxed warning so the user
         * cannot miss it. */
        text_at(0, row++, "  +----------------------+");
        text_at(0, row++, "  |  DRAINER-GRADE CALL  |");
        text_at(0, row++, "  +----------------------+");
        row++;
    }

    for (u32 i = 0; i < d->num_args; i++) {
        if (row >= 17) {
            text_at(0, row, "  (+more args — see hex)");
            break;
        }
        row = render_one_arg(row, &d->args[i], d->fn->args[i].name);
    }

    if (extra_pages_after > 0) {
        text_statusbar("A sign  B cancel  R> raw hex");
    } else {
        text_statusbar("A sign  B cancel  L< back");
    }
}

int confirm_tx(const eth_tx* tx, const tx_meta* meta) {
    /* Pre-decode of the data field. If we recognise a known selector
     * we insert a "DECODED" page between page 0 (header) and the hex
     * pages. */
    eth_abi_call abi;
    int has_abi = eth_abi_decode(tx->data, tx->data_len, &abi);
    if (!has_abi) abi.kind = ETH_ABI_UNKNOWN;

    /* v0.3: generic ABI decoder. Only used as a FALLBACK when the
     * legacy decoder above didn't claim the selector — this keeps the
     * specialised "INFINITE APPROVAL" / "ALL NFTS APPROVED" pretty
     * rendering intact for the 7 selectors v0.2 already covered, while
     * adding parsed views for the ~18 new selectors (Uniswap V2 router,
     * permit, multicall, Universal Router execute, ...). */
    abi_decoded_t decoded;
    int has_parsed = 0;
    if (!has_abi) {
        if (abi_decode(tx->data, tx->data_len, &decoded) == ABI_DEC_OK) {
            has_parsed = 1;
        }
    }

    u32 hex_pages   = data_total_pages(tx->data_len);
    u32 has_decoded_extra = (has_abi || has_parsed) ? 1u : 0u;
    u32 extra_pages = has_decoded_extra + hex_pages;

    /* Page layout:
     *   cur_page == 0:                          header
     *   cur_page == 1 && has_abi:               decoded
     *   cur_page == 1..extra (no abi):          hex page (cur_page - 1)
     *   cur_page == 2..extra (with abi):        hex page (cur_page - 2)
     */
    u32 cur_page = 0;
    int dirty    = 1;

    /* Precomputes the signing hash to display it as "TX ID". The user
     * compares the first 4 bytes with the "TX ID" shown by the PC
     * extension. If they differ, there is a MITM and they MUST NOT
     * sign. The cost is one RLP encode + keccak, both fast (<<1s on
     * the GBA). */
    u8 signing_hash[32];
    eth_tx_signing_hash(tx, signing_hash);

    /* Chain lookup by chainId. If unknown (custom chain added by the
     * user in the extension via wallet_addEthereumChain) we fall back
     * to the GENERIC icon and "?" abbreviation. The numeric chainId
     * keeps showing to avoid ambiguity. */
    const chain_info* ci = chains_lookup((u32)tx->chainid);
    if (!ci) ci = chains_unknown();

    /* blink of the "tx pending" asterisk */
    int blink = 1;
    int frame = 0;

    for (;;) {
        if (dirty) {
            if (cur_page == 0) {
                render_page0(tx, ci, signing_hash, &abi,
                             has_parsed ? &decoded : 0, meta, extra_pages);
            } else if (has_abi && cur_page == 1) {
                render_decoded_page(tx, ci, &abi, meta, extra_pages - 1);
            } else if (has_parsed && cur_page == 1) {
                render_parsed_page(tx, ci, &decoded, meta, extra_pages - 1);
            } else {
                u32 hex_idx = cur_page - 1 - has_decoded_extra;
                /* Blind iff nothing decoded the calldata: the only thing
                 * the user sees of the data field is these hex bytes,
                 * so the hex view's titlebar / page counter shout
                 * "BLIND!" too. */
                int is_blind = !has_abi && !has_parsed;
                render_data_page(tx, hex_idx, hex_pages, is_blind);
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

        if (k & KEY_A) { return 1; }
        if (k & KEY_B) { return 0; }
        if ((k & KEY_R) && cur_page < extra_pages) { cur_page++; dirty = 1; }
        if ((k & KEY_L) && cur_page > 0)           { cur_page--; dirty = 1; }
    }
}

/* Waits for the user to release any key. Calling this before leaving
 * an "A continue" screen prevents the keypress from carrying over to
 * the next one. Defensive: keysDown() already does edge detection, but
 * classic hardware wallets do this anyway for robustness against
 * key-repeat or dropped frames. */
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

/* Address verification screen. The address is split into 2 lines of
 * 22 chars + the remainder. It's framed in an ASCII box and the first
 * 4 / last 4 hex chars are highlighted for at-a-glance comparison with
 * the address shown by the host/extension. */
void confirm_show_address(const u8 address[20]) {
    text_clear();
    text_titlebar("ETH ADDRESS", "VERIFY");

    text_at(0, 3, "  derived account:");

    char addr[43];
    eth_address_to_eip55(address, addr);   /* "0x" + 40 hex + NUL */

    /* ASCII frame to highlight the address */
    text_at(0, 5,  "  +----------------------+");
    char line[40];
    /* first line: 0x + 20 hex (= 22 chars) */
    snprintf(line, sizeof(line), "  | %.22s |", addr);
    text_at(0, 6, line);
    /* second line: 20 remaining hex, padded to 22 */
    snprintf(line, sizeof(line), "  | %-22s |", addr + 22);
    text_at(0, 7, line);
    text_at(0, 8,  "  +----------------------+");

    /* "first...last" summary for at-a-glance comparison */
    snprintf(line, sizeof(line), "  short: %.6s..%s", addr, addr + 38);
    text_at(0, 10, line);

    text_at(0, 13, "  Verify if this is");
    text_at(0, 14, "  your address.");

    text_at(0, 16, "  >> A = continue");
    text_at(0, 17, "  >> B = cancel session");

    text_statusbar("A continue  B cancel session");

    int blink = 1;
    int frame = 0;
    for (;;) {
        VBlankIntrWait();
        input_poll();
        u16 k = input_pressed();
        if (k & KEY_A) { wait_release(); return; }
        if (k & KEY_B) {
            /* For "cancel" to work the caller would have to detect it.
             * Since this API returns void today, we treat it as
             * "continue" too so the user is not stuck. The caller does
             * confirm_yes_no("Save?") right after and that's where the
             * user can say no. */
            wait_release();
            return;
        }
        if ((++frame & 31) == 0) {
            text_at(28, 0, blink ? "*" : " ");
            blink = !blink;
        }
    }
}

/* Initial frame of "BROADCASTING...". The sign_loop does its own
 * cooperative loop on top animating the spinner at (28, 10) (same
 * coords as awaiting transaction for visual continuity). */
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

/* === Paginated text for personal_sign / typed_data ===
 * Layout:
 *   row 0  titlebar
 *   row 2  counter "page X / Y" or "msg (N bytes)"
 *   row 3-18  content (16 lines x 28 usable cols)
 *   row 19 statusbar
 *
 * The "wrap" treats the text as opaque UTF-8 bytes: cuts by byte
 * without splitting multibyte (best effort) or hard-cuts if the byte
 * isn't visible ASCII. Not a full word-wrap, but good enough for SIWE
 * messages, permits, etc. (most fit without fighting).
 */
#define TEXT_COLS_PER_LINE 28
#define TEXT_LINES_PER_PAGE 16

/* Renders a specific text page. Returns the next byte position (for
 * the next page) and the number of lines drawn in *out_lines. */
static u32 render_text_page(const u8* text, u32 len, u32 byte_offset,
                            u32 row_top, u32 max_lines, u32* out_lines) {
    char line_buf[TEXT_COLS_PER_LINE + 1];
    u32 col = 0;
    u32 line = 0;
    u32 i = byte_offset;

    while (i < len && line < max_lines) {
        u8 c = text[i];
        if (c == '\n') {
            line_buf[col] = '\0';
            text_at(1, row_top + line, line_buf);
            line++;
            col = 0;
            i++;
            continue;
        }
        /* replace non-printables with '.' so the render doesn't break */
        char ch = (c >= 0x20 && c < 0x7F) ? (char)c : '.';
        line_buf[col++] = ch;
        i++;
        if (col == TEXT_COLS_PER_LINE) {
            line_buf[col] = '\0';
            text_at(1, row_top + line, line_buf);
            line++;
            col = 0;
        }
    }
    if (col > 0 && line < max_lines) {
        line_buf[col] = '\0';
        text_at(1, row_top + line, line_buf);
        line++;
    }
    *out_lines = line;
    return i;
}

/* Computes the byte_offset of each page by pre-walking. Returns the
 * total number of pages (>= 1) and fills page_offsets[0..N-1] with the
 * byte_offset of each page (page_offsets[0] is always 0). */
static u32 compute_page_offsets(const u8* text, u32 len,
                                u32 max_pages, u32* page_offsets) {
    if (max_pages == 0) return 0;
    page_offsets[0] = 0;
    if (len == 0) return 1;

    u32 col = 0;
    u32 line_in_page = 0;
    u32 page = 0;

    for (u32 i = 0; i < len; ) {
        u8 c = text[i];
        if (c == '\n') {
            line_in_page++;
            col = 0;
            i++;
        } else {
            col++;
            i++;
            if (col == TEXT_COLS_PER_LINE) {
                line_in_page++;
                col = 0;
            }
        }
        if (line_in_page == TEXT_LINES_PER_PAGE) {
            page++;
            if (page >= max_pages) return max_pages;
            page_offsets[page] = i;
            line_in_page = 0;
            col = 0;
        }
    }
    return page + 1;
}

#define MAX_TEXT_PAGES 32

static void render_personal_page(const u8* msg, u32 msglen,
                                 u32 page, u32 npages, u32 byte_offset) {
    char buf[40];
    text_clear();
    text_titlebar("PERSONAL SIGN", "WAIT");

    snprintf(buf, sizeof(buf), "  msg %lu B  page %lu/%lu",
             (unsigned long)msglen,
             (unsigned long)(page + 1), (unsigned long)npages);
    text_at(0, 2, buf);

    u32 drawn;
    render_text_page(msg, msglen, byte_offset, 3, TEXT_LINES_PER_PAGE, &drawn);

    if (npages == 1) {
        text_statusbar("A sign  B cancel");
    } else if (page == 0) {
        text_statusbar("A sign  B cancel  R msg >");
    } else if (page + 1 == npages) {
        text_statusbar("A sign  B cancel  L< msg");
    } else {
        text_statusbar("A sign  B cancel  L< R> msg");
    }
}

/* === Connect approval ===================================================
 * Screen that shows the dApp's origin and asks A/B. Layout:
 *
 *   [CONNECT REQUEST       WAIT]
 *   =============================
 *
 *     A dApp is requesting
 *     access to your wallet
 *     address:
 *
 *     +-----------------------+
 *     | app.uniswap.org       |
 *     +-----------------------+
 *
 *     >> A = ALLOW
 *     >> B = DENY
 *
 *     Approving lets this site
 *     READ your address only.
 *     It cannot sign anything
 *     without further consent.
 *
 *   -----------------------------
 *   A allow  B deny
 *
 * The origin is truncated to 22 chars on screen (no scrolling, just
 * trimming for now). A user verifying an origin >22 chars has to
 * partially trust the truncation. For typical dApps (uniswap, opensea,
 * aave, etc.) it fits with margin.
 * ======================================================================== */
int confirm_connect_request(const char* origin, u32 origin_len) {
    char buf[40];
    char clean[META_ORIGIN_MAX + 1];

    /* Sanitise: only printable ASCII to avoid control codes painting
     * weird chars on screen. Cap at META_ORIGIN_MAX. */
    u32 olen = origin_len < META_ORIGIN_MAX ? origin_len : META_ORIGIN_MAX;
    for (u32 i = 0; i < olen; i++) {
        u8 c = (u8)origin[i];
        clean[i] = (c >= 0x20 && c < 0x7F) ? (char)c : '?';
    }
    clean[olen] = '\0';

    text_clear();
    text_titlebar("CONNECT REQ", "WAIT");

    text_at(0, 3, "  a dApp is requesting");
    text_at(0, 4, "  access to your wallet");
    text_at(0, 5, "  address:");

    /* ASCII frame with the origin. If longer than 22 chars, truncates. */
    text_at(0, 7,  "  +----------------------+");
    snprintf(buf, sizeof(buf), "  | %-22.22s |", clean);
    text_at(0, 8, buf);
    if (olen > 22) {
        snprintf(buf, sizeof(buf), "  | %-22.22s |", clean + 22);
        text_at(0, 9, buf);
        text_at(0, 10, "  +----------------------+");
    } else {
        text_at(0, 9,  "  +----------------------+");
    }

    text_at(0, 12, "  >> A = ALLOW");
    text_at(0, 13, "  >> B = DENY");

    text_at(0, 15, "  Allow = read address.");
    text_at(0, 16, "  Signing tx/msgs always");
    text_at(0, 17, "  asks again separately.");

    text_statusbar("A allow  B deny");

    int blink = 1;
    int frame = 0;
    for (;;) {
        VBlankIntrWait();
        input_poll();
        if ((++frame & 31) == 0) {
            text_at(28, 0, blink ? "*" : " ");
            blink = !blink;
        }
        u16 k = input_pressed();
        if (k & KEY_A) { wait_release(); return 1; }
        if (k & KEY_B) { wait_release(); return 0; }
    }
}

int confirm_personal_sign(const u8* msg, u32 msglen) {
    u32 page_offsets[MAX_TEXT_PAGES];
    u32 npages = compute_page_offsets(msg, msglen, MAX_TEXT_PAGES, page_offsets);
    if (npages == 0) npages = 1;

    u32 cur = 0;
    int dirty = 1;
    int blink = 1;
    int frame = 0;

    for (;;) {
        if (dirty) {
            render_personal_page(msg, msglen, cur, npages, page_offsets[cur]);
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
        if (k & KEY_A) { wait_release(); return 1; }
        if (k & KEY_B) { wait_release(); return 0; }
        if ((k & KEY_R) && cur + 1 < npages) { cur++; dirty = 1; }
        if ((k & KEY_L) && cur > 0)          { cur--; dirty = 1; }
    }
}

/* Renders a pair of truncated hashes (8 chars each side) for manual
 * verification against ethers.js / etherscan / the wallet UI. */
static void render_hash_short(u32 row, const char* label,
                              const u8 hash[32]) {
    static const char H[] = "0123456789abcdef";
    char buf[40];
    char hex[65];
    for (u32 i = 0; i < 32; i++) {
        hex[i * 2 + 0] = H[(hash[i] >> 4) & 0xF];
        hex[i * 2 + 1] = H[ hash[i]       & 0xF];
    }
    hex[64] = '\0';
    snprintf(buf, sizeof(buf), "  %s %.8s..%s", label, hex, hex + 56);
    text_at(0, row, buf);
}

static void render_typed_page(const char* text, u32 textlen,
                              const u8 domain_sep[32], const u8 msg_hash[32],
                              u32 page, u32 npages, u32 byte_offset,
                              int last_page_is_hashes,
                              int parsed_available) {
    char buf[40];
    text_clear();
    text_titlebar("TYPED DATA", "WAIT");

    if (last_page_is_hashes && page + 1 == npages) {
        snprintf(buf, sizeof(buf), "  EIP-712 hashes  page %lu/%lu",
                 (unsigned long)(page + 1), (unsigned long)npages);
        text_at(0, 2, buf);
        text_at(0, 4, "  verify against your");
        text_at(0, 5, "  dApp / ethers.js / wallet:");
        render_hash_short(8,  "domainSep:", domain_sep);
        render_hash_short(10, "msgHash :", msg_hash);
        if (parsed_available) {
            text_at(0, 13, "  Cartridge already verified");
            text_at(0, 14, "  these on-device.");
            text_at(0, 15, "  L+R: back to parsed view.");
        } else {
            text_at(0, 13, "  GBA could NOT parse this");
            text_at(0, 14, "  typed-data on-device.");
            text_at(0, 15, "  Trust the host for these");
            text_at(0, 16, "  hashes; verify text above.");
        }
    } else {
        snprintf(buf, sizeof(buf), "  text %lu B  page %lu/%lu",
                 (unsigned long)textlen,
                 (unsigned long)(page + 1), (unsigned long)npages);
        text_at(0, 2, buf);
        u32 drawn;
        render_text_page((const u8*)text, textlen, byte_offset, 3,
                         TEXT_LINES_PER_PAGE, &drawn);
    }

    if (parsed_available) {
        if (npages == 1) {
            text_statusbar("A sign  B cancel  L+R parse");
        } else if (page == 0) {
            text_statusbar("A B  R>  L+R parse");
        } else if (page + 1 == npages) {
            text_statusbar("A B  L<  L+R parse");
        } else {
            text_statusbar("A B  L< R>  L+R parse");
        }
    } else {
        if (npages == 1) {
            text_statusbar("A sign  B cancel");
        } else if (page == 0) {
            text_statusbar("A sign  B cancel  R hash >");
        } else if (page + 1 == npages) {
            text_statusbar("A sign  B cancel  L< text");
        } else {
            text_statusbar("A sign  B cancel  L< R>");
        }
    }
}

/* ============================================================================
 * v7 EIP-712 parsed view
 *
 * When the host provided a TLV tree and the on-device parser matches the
 * hashes, the user can press L+R to switch from the blind text view to a
 * parsed listing. Lines are pre-rendered into a flat, indented array
 * (one struct field per line; nested structs are indented further) and
 * paginated like the text view. Atomic values are formatted in-place:
 *   - address     -> 0x12345678..AABB
 *   - bool        -> true / false
 *   - uintN/intN  -> decimal if it fits in 64 bits, else 0x<low16>... hex
 *   - bytesN      -> 0x<hex truncado>
 *   - string      -> "<truncated>"
 *   - bytes       -> 0x<hex truncado>
 * ============================================================================ */

#define PARSED_MAX_LINES   96u
#define PARSED_LINE_CHARS  29u   /* 28 visible + indent before label fits within 32 cols */

typedef struct {
    char text[PARSED_LINE_CHARS + 1];
} parsed_line_t;

/* Lives in EWRAM along with the rest of the typed-data workspace
 * (~3 KB; negligible). Reused across confirm calls. */
static EWRAM_BSS parsed_line_t g_parsed_lines[PARSED_MAX_LINES];
static u32 g_parsed_line_count;
static u8  g_parsed_overflow;   /* set when more than PARSED_MAX_LINES were needed */

static int eip712_find_struct(const eip712_tree_t* t, const u8* name, u32 name_len) {
    for (u8 i = 0; i < t->num_types; i++) {
        if (t->types[i].name_len == name_len &&
            memcmp(t->tlv_base + t->types[i].name_off, name, name_len) == 0) {
            return i;
        }
    }
    return -1;
}

static int type_starts_with(const u8* s, u32 len, const char* pre) {
    u32 p = strlen(pre);
    return len >= p && memcmp(s, pre, p) == 0;
}

/* Truncates b into hex form "0x1234..abcd" capped at `cap` chars. */
static void short_hex_into(char* out, u32 cap, const u8* b, u32 n) {
    if (cap < 13) { if (cap) out[0] = '\0'; return; }
    if (n <= 4) {
        out[0] = '0'; out[1] = 'x';
        for (u32 i = 0; i < n; i++) {
            static const char hexd[] = "0123456789abcdef";
            out[2 + i * 2] = hexd[(b[i] >> 4) & 0xF];
            out[3 + i * 2] = hexd[b[i] & 0xF];
        }
        out[2 + n * 2] = '\0';
        return;
    }
    static const char hexd[] = "0123456789abcdef";
    out[0] = '0'; out[1] = 'x';
    for (int i = 0; i < 4; i++) {
        out[2 + i * 2] = hexd[(b[i] >> 4) & 0xF];
        out[3 + i * 2] = hexd[b[i] & 0xF];
    }
    out[10] = '.'; out[11] = '.';
    for (int i = 0; i < 2; i++) {
        out[12 + i * 2] = hexd[(b[n - 2 + i] >> 4) & 0xF];
        out[13 + i * 2] = hexd[b[n - 2 + i] & 0xF];
    }
    out[16] = '\0';
}

/* Reads N raw bytes (big-endian) as an unsigned value. If N > 8 the
 * function only reads the LOW 8 bytes (after verifying the high bytes
 * are zero). Returns 1 if the value fit in u64, 0 otherwise. */
static int read_uint_be_u64(const u8* p, u32 n, u64* out) {
    if (n == 0) { *out = 0; return 1; }
    if (n > 8) {
        for (u32 i = 0; i < n - 8; i++) {
            if (p[i] != 0) return 0;
        }
        p += n - 8;
        n = 8;
    }
    u64 v = 0;
    for (u32 i = 0; i < n; i++) {
        v = (v << 8) | (u64)p[i];
    }
    *out = v;
    return 1;
}

/* Formats one atomic / dynamic value into `out` (capped at `cap` chars).
 * `cursor` is advanced past the value bytes consumed. Returns 0 on OK,
 * -1 on malformed; the line is left as "<bad>" on errors. */
static int format_atomic_value(const eip712_tree_t* t,
                               const u8* type_str, u32 type_len,
                               u32* cursor, char* out, u32 cap) {
    if (cap < 2) { if (cap) out[0] = '\0'; return -1; }
    const u8* tlv = t->tlv_base;
    u32 tlv_len = t->tlv_len;

    /* string */
    if (type_len == 6 && memcmp(type_str, "string", 6) == 0) {
        if (*cursor + 4 > tlv_len) { snprintf(out, cap, "<bad>"); return -1; }
        u32 slen = ((u32)tlv[*cursor] << 24) | ((u32)tlv[*cursor + 1] << 16) |
                   ((u32)tlv[*cursor + 2] << 8) | tlv[*cursor + 3];
        *cursor += 4;
        if (*cursor + slen > tlv_len) { snprintf(out, cap, "<bad>"); return -1; }
        u32 show = slen < (cap - 3) ? slen : (cap - 4);
        out[0] = '"';
        memcpy(out + 1, tlv + *cursor, show);
        if (show < slen) { out[1 + show++] = '~'; }
        out[1 + show] = '"';
        out[2 + show] = '\0';
        *cursor += slen;
        return 0;
    }

    /* dynamic bytes */
    if (type_len == 5 && memcmp(type_str, "bytes", 5) == 0) {
        if (*cursor + 4 > tlv_len) { snprintf(out, cap, "<bad>"); return -1; }
        u32 slen = ((u32)tlv[*cursor] << 24) | ((u32)tlv[*cursor + 1] << 16) |
                   ((u32)tlv[*cursor + 2] << 8) | tlv[*cursor + 3];
        *cursor += 4;
        if (*cursor + slen > tlv_len) { snprintf(out, cap, "<bad>"); return -1; }
        short_hex_into(out, cap, tlv + *cursor, slen);
        *cursor += slen;
        return 0;
    }

    /* address */
    if (type_len == 7 && memcmp(type_str, "address", 7) == 0) {
        if (*cursor + 20 > tlv_len) { snprintf(out, cap, "<bad>"); return -1; }
        short_hex_into(out, cap, tlv + *cursor, 20);
        *cursor += 20;
        return 0;
    }

    /* bool */
    if (type_len == 4 && memcmp(type_str, "bool", 4) == 0) {
        if (*cursor + 1 > tlv_len) { snprintf(out, cap, "<bad>"); return -1; }
        snprintf(out, cap, "%s", tlv[*cursor] ? "true" : "false");
        *cursor += 1;
        return 0;
    }

    /* uintN / intN */
    if (type_starts_with(type_str, type_len, "uint") || type_starts_with(type_str, type_len, "int")) {
        u32 prefix = type_starts_with(type_str, type_len, "uint") ? 4 : 3;
        u32 bits = 256;
        if (type_len > prefix) {
            bits = 0;
            for (u32 i = prefix; i < type_len; i++) {
                if (type_str[i] < '0' || type_str[i] > '9') { snprintf(out, cap, "<bad>"); return -1; }
                bits = bits * 10 + (type_str[i] - '0');
            }
        }
        if (bits == 0 || bits > 256 || (bits & 7) != 0) { snprintf(out, cap, "<bad>"); return -1; }
        u32 nbytes = bits / 8;
        if (*cursor + nbytes > tlv_len) { snprintf(out, cap, "<bad>"); return -1; }
        /* "infinite" sentinel: all-ones for uint128 or wider. Covers both
         * ERC-20 approve (uint256 max = 2^256-1) and Permit2 amount
         * (uint160 max = 2^160-1), which dApps use to mean "no cap". */
        if (nbytes >= 16) {
            int all_ones = 1;
            for (u32 i = 0; i < nbytes; i++) {
                if (tlv[*cursor + i] != 0xff) { all_ones = 0; break; }
            }
            if (all_ones) {
                snprintf(out, cap, "MAX (infinite)");
                *cursor += nbytes;
                return 0;
            }
        }
        u64 v;
        if (read_uint_be_u64(tlv + *cursor, nbytes, &v)) {
            u64_to_str(v, out, cap);
        } else {
            /* value too big for u64 - show as hex of the low 16 bytes
             * prefixed with "0x" so the user knows it overflowed. */
            u32 hex_bytes = nbytes < 16 ? nbytes : 16;
            const u8* base = tlv + *cursor + (nbytes - hex_bytes);
            short_hex_into(out, cap, base, hex_bytes);
        }
        *cursor += nbytes;
        return 0;
    }

    /* bytesN (1..32) */
    if (type_starts_with(type_str, type_len, "bytes")) {
        u32 n = 0;
        for (u32 i = 5; i < type_len; i++) {
            if (type_str[i] < '0' || type_str[i] > '9') { snprintf(out, cap, "<bad>"); return -1; }
            n = n * 10 + (type_str[i] - '0');
        }
        if (n < 1 || n > 32) { snprintf(out, cap, "<bad>"); return -1; }
        if (*cursor + n > tlv_len) { snprintf(out, cap, "<bad>"); return -1; }
        short_hex_into(out, cap, tlv + *cursor, n);
        *cursor += n;
        return 0;
    }

    snprintf(out, cap, "<unsup>");
    return -1;
}

/* Adds one line to the parsed-line buffer (with truncation if it
 * overflows the cap). Caller is responsible for advancing whatever
 * cursor it walks. */
static void push_line(const char* fmt, ...) {
    if (g_parsed_line_count >= PARSED_MAX_LINES) {
        g_parsed_overflow = 1;
        return;
    }
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(g_parsed_lines[g_parsed_line_count].text,
              sizeof(g_parsed_lines[g_parsed_line_count].text), fmt, ap);
    va_end(ap);
    g_parsed_line_count++;
}

/* Walks a struct's values, emitting one parsed_line per field. Recurses
 * into nested structs (with deeper indent). */
static void walk_struct_for_lines(const eip712_tree_t* t, u8 type_idx,
                                  u32* cursor, u8 depth) {
    if (depth >= EIP712_MAX_DEPTH || type_idx >= t->num_types) return;
    const eip712_type_t* ty = &t->types[type_idx];
    char indent[12];
    u8 ind = depth * 2;
    if (ind > 10) ind = 10;
    memset(indent, ' ', ind);
    indent[ind] = '\0';

    for (u8 i = 0; i < ty->num_fields; i++) {
        const eip712_field_t* f = &ty->fields[i];
        const u8* ftype = t->tlv_base + f->type_off;
        u8 ftype_len = f->type_len;
        const u8* fname = t->tlv_base + f->name_off;
        u8 fname_len = f->name_len;

        /* Arrays (never reached when status == OK_MATCH but defensive). */
        if (ftype_len > 0 && ftype[ftype_len - 1] == ']') {
            push_line("%s%.*s: <array>", indent, (int)fname_len, fname);
            return;
        }

        s32 child_idx = eip712_find_struct(t, ftype, ftype_len);
        if (child_idx >= 0) {
            push_line("%s%.*s:", indent, (int)fname_len, fname);
            walk_struct_for_lines(t, (u8)child_idx, cursor, depth + 1);
            continue;
        }

        char valbuf[24];
        format_atomic_value(t, ftype, ftype_len, cursor, valbuf, sizeof(valbuf));
        push_line("%s%.*s: %s", indent, (int)fname_len, fname, valbuf);
    }
}

/* Top-level build: emit a "Domain:" header, walk EIP712Domain values,
 * blank line, "<PrimaryType>:" header, walk the message values. */
static void build_parsed_lines(const eip712_tree_t* t) {
    g_parsed_line_count = 0;
    g_parsed_overflow = 0;

    /* domain */
    push_line("Domain:");
    u32 cursor = t->domain_values_off;
    walk_struct_for_lines(t, 0, &cursor, 1);

    if (g_parsed_line_count < PARSED_MAX_LINES) {
        g_parsed_lines[g_parsed_line_count++].text[0] = '\0';   /* blank line */
    }

    /* message */
    const eip712_type_t* pty = &t->types[t->primary_type_index];
    push_line("%.*s:", (int)pty->name_len, t->tlv_base + pty->name_off);
    cursor = t->message_values_off;
    walk_struct_for_lines(t, t->primary_type_index, &cursor, 1);
}

#define PARSED_LINES_PER_PAGE  13u

static u32 parsed_total_pages(void) {
    if (g_parsed_line_count == 0) return 1;
    return (g_parsed_line_count + PARSED_LINES_PER_PAGE - 1) / PARSED_LINES_PER_PAGE;
}

static void render_typed_parsed_page(const eip712_tree_t* t, u32 page, u32 npages) {
    char buf[40];
    text_clear();
    text_titlebar("TYPED DATA OK", "PARSE");

    /* Header line: primaryType plus chain-id verification glyph. */
    const eip712_type_t* pty = &t->types[t->primary_type_index];
    if (t->has_chain_id) {
        snprintf(buf, sizeof(buf), "%.*s  chain:%lu",
                 (int)pty->name_len, t->tlv_base + pty->name_off,
                 (unsigned long)t->domain_chain_id);
    } else {
        snprintf(buf, sizeof(buf), "%.*s  chain:any",
                 (int)pty->name_len, t->tlv_base + pty->name_off);
    }
    text_at(0, 2, buf);

    snprintf(buf, sizeof(buf), "  pg %lu/%lu  hash MATCH",
             (unsigned long)(page + 1), (unsigned long)npages);
    text_at(0, 3, buf);

    u32 start = page * PARSED_LINES_PER_PAGE;
    for (u32 i = 0; i < PARSED_LINES_PER_PAGE; i++) {
        u32 li = start + i;
        if (li >= g_parsed_line_count) break;
        text_at(0, 5 + i, g_parsed_lines[li].text);
    }

    if (g_parsed_overflow && page + 1 == npages) {
        text_at(0, 18, "(tree truncated)");
    }

    if (npages == 1) {
        text_statusbar("A sign  B cancel  L+R blind");
    } else if (page == 0) {
        text_statusbar("A B  R>  L+R blind");
    } else if (page + 1 == npages) {
        text_statusbar("A B  L<  L+R blind");
    } else {
        text_statusbar("A B  L< R>  L+R blind");
    }
}

static void render_typed_mismatch_page(const eip712_tree_t* t,
                                       const u8 host_ds[32],
                                       const u8 host_mh[32]) {
    text_clear();
    text_titlebar("MISMATCH!", "STOP");
    text_at(0, 2,  "  HOST HASH MISMATCH");
    text_at(0, 4,  "The host sent hashes that");
    text_at(0, 5,  "do NOT match the typed");
    text_at(0, 6,  "data the cartridge parsed.");
    text_at(0, 8,  "This is a strong sign of a");
    text_at(0, 9,  "compromised host. Signing");
    text_at(0, 10, "is BLOCKED.");
    /* Show a couple of bytes of each so the user can see the diff. */
    char buf[40];
    static const char hexd[] = "0123456789abcdef";
    char h1[9], h2[9];
    for (int i = 0; i < 4; i++) {
        h1[i*2]   = hexd[(host_ds[i]>>4)&0xF];
        h1[i*2+1] = hexd[host_ds[i]&0xF];
        h2[i*2]   = hexd[(t->our_domain_separator[i]>>4)&0xF];
        h2[i*2+1] = hexd[t->our_domain_separator[i]&0xF];
    }
    h1[8] = h2[8] = '\0';
    snprintf(buf, sizeof(buf), "  ds host : %s..", h1);
    text_at(0, 13, buf);
    snprintf(buf, sizeof(buf), "  ds ours : %s..", h2);
    text_at(0, 14, buf);
    (void)host_mh;
    text_statusbar("B cancel  (A disabled)");
}

/* Combo detector: L+R held simultaneously, single-press protected.
 * Returns 1 ONCE per combo session. */
typedef struct {
    int single_l_pending;
    int single_r_pending;
    int combo_used;
} lr_combo_state_t;

static void lr_combo_init(lr_combo_state_t* s) {
    s->single_l_pending = 0;
    s->single_r_pending = 0;
    s->combo_used = 0;
}

/* Returns:
 *   +1 if a combo just triggered
 *    0 if nothing actionable
 *   -1 if L was just released as a single (caller pages left)
 *   -2 if R was just released as a single (caller pages right) */
static int lr_combo_step(lr_combo_state_t* s, u16 pressed, u16 held, u16 released) {
    if (pressed & KEY_L) s->single_l_pending = 1;
    if (pressed & KEY_R) s->single_r_pending = 1;

    int both_held = (held & (KEY_L|KEY_R)) == (KEY_L|KEY_R);
    if (both_held) {
        s->single_l_pending = 0;
        s->single_r_pending = 0;
        if (!s->combo_used) {
            s->combo_used = 1;
            return 1;
        }
        return 0;
    }

    if (!(held & (KEY_L|KEY_R))) {
        s->combo_used = 0;
    }

    if ((released & KEY_L) && s->single_l_pending) {
        s->single_l_pending = 0;
        return -1;
    }
    if ((released & KEY_R) && s->single_r_pending) {
        s->single_r_pending = 0;
        return -2;
    }
    return 0;
}

int confirm_typed_data(const char* text, u32 textlen,
                       const u8 domain_sep[32], const u8 msg_hash[32],
                       const eip712_tree_t* tree,
                       eip712_status_t parse_status) {
    /* Build the parsed-line buffer up front if the tree is verifiable.
     * It's cheap (~few ms for typical payloads) and means the L+R
     * toggle is instantaneous. */
    int parsed_available = (tree != NULL && parse_status == EIP712_OK_MATCH);
    int mismatch = (tree != NULL && parse_status == EIP712_OK_MISMATCH);
    if (parsed_available) {
        build_parsed_lines(tree);
    }

    /* If the host clearly lied about the hashes, refuse to sign before
     * the user even gets a chance to. Only B is honoured. */
    if (mismatch) {
        int dirty = 1;
        for (;;) {
            if (dirty) {
                render_typed_mismatch_page(tree, domain_sep, msg_hash);
                dirty = 0;
            }
            VBlankIntrWait();
            input_poll();
            u16 k = input_pressed();
            if (k & KEY_B) { wait_release(); return 0; }
        }
    }

    u32 page_offsets[MAX_TEXT_PAGES];
    u32 text_pages = compute_page_offsets((const u8*)text, textlen,
                                          MAX_TEXT_PAGES - 1, page_offsets);
    if (text_pages == 0) text_pages = 1;
    u32 blind_npages = text_pages + 1;   /* +1 for the hashes recap page */
    u32 parsed_npages = parsed_available ? parsed_total_pages() : 0;

    /* Default: parsed view when the cartridge could re-derive the hashes;
     * fall back to blind view (raw text + hex hashes) otherwise. The user
     * can still toggle to the blind hex view with L+R if they want to
     * eyeball the raw hashes. */
    int show_parsed = parsed_available ? 1 : 0;
    u32 cur_blind = 0;
    u32 cur_parsed = 0;
    int dirty = 1;
    int blink = 1;
    int frame = 0;

    lr_combo_state_t lrs;
    lr_combo_init(&lrs);

    for (;;) {
        if (dirty) {
            if (show_parsed) {
                render_typed_parsed_page(tree, cur_parsed, parsed_npages);
            } else {
                u32 byte_off = (cur_blind < text_pages) ? page_offsets[cur_blind] : 0;
                render_typed_page(text, textlen, domain_sep, msg_hash,
                                  cur_blind, blind_npages, byte_off, 1,
                                  parsed_available);
            }
            dirty = 0;
        }
        VBlankIntrWait();
        input_poll();

        if ((++frame & 31) == 0) {
            text_at(28, 0, blink ? "*" : " ");
            blink = !blink;
        }

        u16 pressed  = input_pressed();
        u16 held     = input_held();
        u16 released = input_released();

        if (pressed & KEY_A) { wait_release(); return 1; }
        if (pressed & KEY_B) { wait_release(); return 0; }

        int combo = parsed_available ? lr_combo_step(&lrs, pressed, held, released) : 0;
        if (combo == 1) {
            show_parsed = !show_parsed;
            dirty = 1;
            continue;
        }
        if (combo == -1) {
            if (show_parsed) {
                if (cur_parsed > 0) { cur_parsed--; dirty = 1; }
            } else {
                if (cur_blind > 0) { cur_blind--; dirty = 1; }
            }
            continue;
        }
        if (combo == -2) {
            if (show_parsed) {
                if (cur_parsed + 1 < parsed_npages) { cur_parsed++; dirty = 1; }
            } else {
                if (cur_blind + 1 < blind_npages)   { cur_blind++; dirty = 1; }
            }
            continue;
        }

        /* When the tree isn't parseable we keep the v6 input semantics:
         * single L/R navigate immediately, no combo. */
        if (!parsed_available) {
            if ((pressed & KEY_R) && cur_blind + 1 < blind_npages) { cur_blind++; dirty = 1; }
            if ((pressed & KEY_L) && cur_blind > 0)                { cur_blind--; dirty = 1; }
        }
    }
}

/* Tx result screen. status: see confirm.h. Waits for A. */
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
        /* two lines of 32 hex chars inside the frame (32 + 2 padding
         * bars) but the screen has 30 usable cols, so we split as
         * 22+22+20. */
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
        /* error: show truncated ASCII message */
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

    /* clears previously-pressed keys (the A from confirm_tx can leak through) */
    wait_release();
    for (;;) {
        VBlankIntrWait();
        input_poll();
        if (input_pressed() & KEY_A) { wait_release(); return; }
    }
}

/* === Destructive confirmation: wipe wallet ===
 * Deliberately "annoying" design: the user must HOLD A pressed for
 * WIPE_HOLD_FRAMES (~3s) to confirm. Pressing B or L/R/START aborts.
 * Releasing A resets the counter. We display a progress bar so the
 * gesture is conscious and reversible.
 *
 * Why no PIN re-entry: once in awaiting-tx the GBA is already
 * unlocked — anyone with the powered-on console can sign arbitrary
 * txs via USB. Asking for the PIN here would add no real barrier,
 * only friction. The hold-A gesture DOES protect against accidents
 * (which is the realistic threat).
 */
#define WIPE_HOLD_FRAMES 180  /* 3 seconds at 60 fps */

int confirm_wipe_wallet(void) {
    text_clear();
    text_titlebar("WIPE WALLET", "DANGER");

    text_at(0, 3,  "  !!! IRREVERSIBLE !!!");
    text_at(0, 5,  "  This will erase the");
    text_at(0, 6,  "  encrypted seed from");
    text_at(0, 7,  "  cartridge SRAM.");

    text_at(0, 9,  "  You MUST have your");
    text_at(0, 10, "  12 BIP-39 words backup");
    text_at(0, 11, "  to recover funds.");

    text_at(0, 13, "  Hold A for 3 seconds");
    text_at(0, 14, "  to confirm wipe.");
    text_at(0, 16, "  Any other key cancels.");

    /* Empty progress bar on row 18, inside the frame "[          ]" */
    text_at(0, 18, "  [                    ]");

    text_statusbar("HOLD A to wipe  |  B cancel");

    /* clear residual keypresses (the SELECT that opened this screen) */
    wait_release();

    u32 held_frames = 0;
    int last_filled = -1;
    for (;;) {
        VBlankIntrWait();
        input_poll();
        u16 held = input_held();

        /* Any "non-A" key cancels (B, L, R, START, SELECT, d-pad) */
        const u16 cancel_keys = (u16)(KEY_B | KEY_L | KEY_R | KEY_START
                                    | KEY_SELECT | KEY_UP | KEY_DOWN
                                    | KEY_LEFT | KEY_RIGHT);
        if (held & cancel_keys) {
            wait_release();
            return 0;
        }

        if (held & KEY_A) {
            held_frames++;
            /* 20-char bar mapped onto WIPE_HOLD_FRAMES */
            int filled = (int)((held_frames * 20u) / WIPE_HOLD_FRAMES);
            if (filled > 20) filled = 20;
            if (filled != last_filled) {
                char bar[24];
                bar[0] = ' '; bar[1] = ' '; bar[2] = '['; /* prefix "  [" */
                int j = 3;
                for (int i = 0; i < filled; i++)  bar[j++] = '#';
                for (int i = filled; i < 20; i++) bar[j++] = ' ';
                bar[j++] = ']'; bar[j] = '\0';
                text_at(0, 18, bar);
                last_filled = filled;
            }
            if (held_frames >= WIPE_HOLD_FRAMES) {
                wait_release();
                return 1;
            }
        } else if (held_frames > 0) {
            /* Released A before the 3s: reset the bar. */
            held_frames = 0;
            last_filled = -1;
            text_at(0, 18, "  [                    ]");
        }
    }
}
