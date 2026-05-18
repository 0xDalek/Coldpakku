#ifndef LINK_PROTOCOL_H
#define LINK_PROTOCOL_H

#include "../types.h"

/*
 * Handshake protocol (v4 - multi-opcode: tx + get_address + personal_sign + typed_data):
 *
 *   Common to every flow:
 *     GBA  -> PC : 0xAA                (ready, pulsed every 0.5 s)
 *     PC   -> GBA: 0xBB                (acknowledge)
 *     PC   -> GBA: 1B opcode           (one of PROTO_TX_RLP / PROTO_GET_ADDRESS /
 *                                       PROTO_PERSONAL_SIGN / PROTO_TYPED_DATA)
 *     ... (payload depends on the opcode) ...
 *     GBA  -> PC : 0xCC                (done)
 *
 *   --- PROTO_TX_RLP (0xCD) - Ethereum tx signature ---
 *     PC   -> GBA: 4B len_be + N bytes serialised RLP (N up to PROTO_TX_RLP_MAX)
 *     GBA parses, computes the internal keccak, shows the user, A/B
 *     GBA  -> PC : 0xCE marker SIGSTART
 *     GBA  -> PC : 65B signature (r || s || v=0xFE)   <- v=0xFE sentinel: host computes recid
 *                  or, on cancel: 0xFF
 *
 *   --- PROTO_GET_ADDRESS (0xC0) - reads the active address, no signing ---
 *     PC sends just the opcode (no extra payload)
 *     GBA  -> PC : 0xC1 marker ADDRSTART
 *     GBA  -> PC : 20B address (raw bytes, no checksum)
 *     No user confirmation needed - it is read-only.
 *
 *   --- PROTO_PERSONAL_SIGN (0xD0) - EIP-191 personal_sign signature ---
 *     PC   -> GBA: 4B len_be + N bytes UTF-8 message (up to PROTO_PERSONAL_MSG_MAX)
 *     GBA prepends "\x19Ethereum Signed Message:\n<len>" and hashes with keccak256.
 *     GBA displays the message (text + truncated hex), A to sign / B to cancel.
 *     GBA  -> PC : 0xCE SIGSTART + 65B sig (v = 0xFE sentinel; host computes recid
 *                  exactly as for txs and returns v=27+recid to the dApp)
 *                  or cancel 0xFF
 *
 *   --- PROTO_TYPED_DATA (0xD1) - EIP-712 signature ---
 *     PC   -> GBA: 32B domainSeparator + 32B messageHash
 *                  + 4B text_len + N bytes UTF-8 human text (up to PROTO_TYPED_TEXT_MAX)
 *     GBA computes keccak256(0x1901 || domainSeparator || messageHash) without
 *     parsing EIP-712. GBA shows the human text (pretty-printed by the host)
 *     plus the hashes in truncated hex at the end for manual verification.
 *     A to sign / B to cancel.
 *     GBA  -> PC : 0xCE SIGSTART + 65B sig (v = 0xFE sentinel)
 *                  or cancel 0xFF
 *
 *   --- PROTO_TXRESULT (0xCF) - broadcast feedback (only after PROTO_TX_RLP) ---
 *     PC   -> GBA: 1B status (0x00=BROADCAST_OK, 0x01=BROADCAST_ERR, 0x02=NO_BROADCAST)
 *       if status == 0x00 or 0x02: PC -> GBA: 32B txhash
 *       if status == 0x01:        PC -> GBA: 1B err_len + err_len bytes UTF-8 (max 64)
 *     GBA displays "TX BROADCAST" with hash/error and waits for A. Back-compat:
 *     if an old host doesn't send TXRESULT, the GBA cooperatively times out
 *     (~30 s) and returns on its own.
 *
 *   --- PROTO_GET_POLICY (0xC2) - reads the chain currently locked on the GBA ---
 *     PC sends only the opcode (no extra payload).
 *     GBA  -> PC : 0xC3 marker POLICYSTART
 *     GBA  -> PC : 4B chain_id (big-endian). 0 = ANY (no lock; not used today
 *                  — we always have a network selected — but the value is
 *                  reserved for a future "allow everything" mode).
 *     No user confirmation needed - read-only. The extension uses it on
 *     connect to display "GBA: BASE locked" in the popup badge.
 *
 *   --- PROTO_TX_RLP_META (0xD2) - tx + host-supplied metadata ---
 *     Variant of PROTO_TX_RLP that also carries a metadata block (dApp
 *     origin, contract name, destination token symbol/decimals, ...).
 *     The fields are NOT verifiable by the GBA and are rendered as "host
 *     says X" — same trust model as the EIP-712 human text.
 *
 *     PC -> GBA: 0xD2
 *     PC -> GBA: 4B rlp_len (be)
 *     PC -> GBA: N bytes RLP (same format as PROTO_TX_RLP)
 *     PC -> GBA: 2B meta_len (be, 0..PROTO_TX_META_MAX)
 *     PC -> GBA: M bytes meta TLV
 *
 *     TLV: sequence of [type:1B][len:1B][value:len bytes], greedy until
 *     meta_len bytes are consumed. Unknown types are IGNORED (forward-compat).
 *
 *     Types defined today (META_TYPE_*):
 *       0x01 ORIGIN     str <=96  "app.uniswap.org" (visible ASCII)
 *       0x02 TO_NAME    str <=32  "WETH9" / "Uniswap V3 Router"
 *       0x03 TO_SYMBOL  str <=16  "WETH" / "USDC" / "WBNB"
 *       0x04 TO_DECIMALS u8       0..77 (decimals of `to:` if ERC-20)
 *
 *     After signing the flow is identical to PROTO_TX_RLP: the GBA emits
 *     0xCE SIGSTART + 65B + 0xCC DONE, or 0xFF + 0xCC.
 *
 *     Both opcodes coexist: old hosts keep using 0xCD without meta; new
 *     hosts can keep using 0xCD (no meta) or 0xD2 (with meta). The GBA
 *     accepts either.
 *
 *   --- PROTO_REJECT_CHAIN (0xFD) - chain mismatch rejection ---
 *     Sentinel sent by the GBA INSTEAD OF SIGSTART/CANCEL when a tx
 *     arrives with a chainId different from the one locked on the GBA.
 *     Sent inside the PROTO_TX_RLP flow, right after the RLP payload,
 *     before the DONE.
 *
 *     GBA  -> PC : 0xFD marker REJECT_CHAIN
 *     GBA  -> PC : 4B expected_chain_id (big-endian, what the GBA has
 *                  locked)
 *     GBA  -> PC : 4B got_chain_id (big-endian, what came in on the tx)
 *     GBA  -> PC : 0xCC PROTO_DONE
 *
 *     After this, the GBA shows the "WRONG CHAIN" screen locally and goes
 *     back to READY. The extension reads 0xFD, knows no signature is
 *     coming, reads the 8 bytes and shows the dapp a structured EIP-1193
 *     error: "GBA is locked to <name>; tx is for <name>. Press L/R on
 *     the cartridge to switch."
 */

#define PROTO_READY          0xAA
#define PROTO_ACK            0xBB
#define PROTO_TX_RLP         0xCD
#define PROTO_DONE           0xCC
#define PROTO_SIGSTART       0xCE
#define PROTO_TXRESULT       0xCF
#define PROTO_CANCEL         0xFF

/* v4 */
#define PROTO_GET_ADDRESS    0xC0
#define PROTO_ADDRSTART      0xC1
#define PROTO_PERSONAL_SIGN  0xD0
#define PROTO_TYPED_DATA     0xD1

/* v5: chain lock policy */
#define PROTO_GET_POLICY     0xC2
#define PROTO_POLICYSTART    0xC3
#define PROTO_REJECT_CHAIN   0xFD

/* v6: tx + host-supplied metadata (origin, contract name, token info) */
#define PROTO_TX_RLP_META    0xD2

#define META_TYPE_ORIGIN     0x01   /* ASCII, up to META_ORIGIN_MAX */
#define META_TYPE_TO_NAME    0x02   /* ASCII, up to META_NAME_MAX */
#define META_TYPE_TO_SYMBOL  0x03   /* ASCII, up to META_SYMBOL_MAX */
#define META_TYPE_TO_DECIMALS 0x04  /* 1 byte uint, 0..77 */

#define META_ORIGIN_MAX      96u
#define META_NAME_MAX        32u
#define META_SYMBOL_MAX      16u

/* Hard cap of the meta block. Plenty for the 4 current fields (~150B)
 * and leaves room for 1-2 future fields without breaking the wire. */
#define PROTO_TX_META_MAX    256u

/* v7: heartbeat. The extension sends this opcode every ~5 s while
 * connected. The GBA only uses it to update the 'link:' indicator on
 * AWAITING TRANSACTION (ACTIVE / idle / NONE). No payload, just
 * ACK + opcode + DONE. */
#define PROTO_HEARTBEAT      0xC4

/* v8: connect approval. The extension sends this opcode the first time
 * a dApp calls eth_requestAccounts. Payload = 2B BE len + N bytes
 * ASCII origin (up to META_ORIGIN_MAX = 96). The GBA shows a screen
 *   CONNECT REQUEST
 *     app.uniswap.org
 * and waits for A (approve) or B (deny). Response:
 *   GBA -> PC: 0xC6 PROTO_CONNECT_OK  + 0xCC DONE
 * or, on cancel:
 *   GBA -> PC: 0xFF PROTO_CANCEL      + 0xCC DONE
 *
 * The extension persists approved origins in chrome.storage.local so it
 * doesn't ask again next time (same model as MetaMask). */
#define PROTO_CONNECT_REQUEST 0xC5
#define PROTO_CONNECT_OK      0xC6

/* Status bytes for PROTO_TXRESULT */
#define TXRESULT_BROADCAST_OK   0x00
#define TXRESULT_BROADCAST_ERR  0x01
#define TXRESULT_NO_BROADCAST   0x02

#define TXRESULT_ERRMSG_MAX     64

#define PROTO_TX_TIMEOUT_FRAMES (60 * 30)   /* 30 s at 60 fps */

/* Cap we accept for a tx. Normal EIP-1559 txs fit in <300 bytes;
 * Uniswap swaps or large contract calls rarely exceed 2 KB. 4 KB gives
 * margin and remains trivial in EWRAM. */
#define PROTO_TX_RLP_MAX 4096u

/* Caps for the new opcodes. EWRAM has 256 KB so there's plenty. */
#define PROTO_PERSONAL_MSG_MAX  4096u
#define PROTO_TYPED_TEXT_MAX    4096u

/* Receives opcode + length-prefixed RLP payload from the PC.
 * Writes the bytes into out_buf and the length into *out_len.
 * Returns 1 on OK; 0 on timeout, unexpected opcode, or length >
 * capacity. Compat: legacy "all-in-one" variant. For v4, the caller
 * should read the opcode with protocol_recv_opcode() and then use
 * protocol_recv_lenprefixed() depending on the opcode. */
int protocol_recv_tx_rlp(u8* out_buf, u32 capacity, u32* out_len);

/* Reads 1 opcode byte (busy-spin with timeout). Returns -1 on timeout.
 * Call right after protocol_wait_ack() == 1. */
int protocol_recv_opcode(void);

/* Reads 4B big-endian + N bytes into out_buf. Returns 1 on OK, 0 on
 * timeout or if len exceeds min(capacity, max_total). */
int protocol_recv_lenprefixed(u8* out_buf, u32 capacity, u32 max_total, u32* out_len);

/* 2B-prefix variant (used for the meta block in PROTO_TX_RLP_META).
 * Unlike the 4B variant, it ACCEPTS len == 0 (optional meta).
 * Returns 1 on OK. */
int protocol_recv_lenprefixed_2b(u8* out_buf, u32 capacity, u32 max_total, u32* out_len);

/* Sends: SIGSTART byte (0xCE) + 65B sig. The SIGSTART lets the host
 * resynchronise by discarding residual READYs from the previous pulse
 * cycle. */
void protocol_send_sig(const u8 sig[65]);

/* Sends: ADDRSTART byte (0xC1) + 20B address. */
void protocol_send_address(const u8 address[20]);

/* Sends: POLICYSTART byte (0xC3) + 4B chain_id (big-endian). 0 = ANY. */
void protocol_send_policy(u32 chain_id);

/* Sends: CONNECT_OK byte (0xC6). Simple marker, no payload. */
void protocol_send_connect_ok(void);

/* Sends: REJECT_CHAIN byte (0xFD) + 4B expected (big-endian) + 4B got
 * (big-endian). Used when a tx arrives with a chainId that doesn't
 * match the one locked on the GBA (see state.c handle_tx_rlp). */
void protocol_send_reject_chain(u32 expected, u32 got);

void protocol_send_cancel(void);
void protocol_send_done(void);

void protocol_send_ready(void);
int  protocol_wait_ack(void);

#endif
