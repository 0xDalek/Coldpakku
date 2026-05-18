#ifndef UI_CONFIRM_H
#define UI_CONFIRM_H

#include "../types.h"
#include "../crypto/eth_tx.h"
#include "../link/tx_meta.h"

/* Shows the confirmation screen with all the parsed tx fields (nonce,
 * fees, gas, EIP-55 to, value, data with pagination if long). If `meta`
 * is not NULL and carries fields, they are rendered as "host says X"
 * (origin, contract name, token symbol/decimals). Returns 1 if the user
 * presses A (confirm), 0 if they press B. */
int confirm_tx(const eth_tx* tx, const tx_meta* meta);

/* Generic yes/no prompt. */
int confirm_yes_no(const char* prompt);

/* Shows a 20-byte address for visual verification. Waits for A. */
void confirm_show_address(const u8 address[20]);

/* Tx result after attempting broadcast on the host.
 *
 *   status = 0x00 : broadcast OK   -> hash[32] valid, errmsg ignored
 *   status = 0x01 : broadcast ERR  -> errmsg/errlen valid, hash ignored
 *   status = 0x02 : NO BROADCAST   -> signed OK but host did not send (audit mode)
 *
 * Waits for A to return. */
void confirm_show_tx_result(u8 status,
                            const u8 hash[32],
                            const char* errmsg, u32 errlen);

/* "BROADCASTING..." screen with cooperative spinner, shown while we
 * wait for PROTO_TXRESULT from the host. Paints only the initial frame;
 * the caller does its own loop animating the spinner. */
void confirm_show_broadcasting(void);

/* Confirms an EIP-191 personal_sign signature. Displays the message on
 * screen (paginated if long). Returns 1 if A (sign), 0 if B (cancel). */
int confirm_personal_sign(const u8* msg, u32 msglen);

/* Confirms an EIP-712 typed_data signature. Displays the pretty-printed
 * human text the host produced (domain.name/version/chainId/
 * verifyingContract + message), and the domainSeparator and messageHash
 * hashes in truncated hex at the end for manual verification. Returns
 * 1 if A (sign), 0 if B (cancel). */
int confirm_typed_data(const char* text, u32 textlen,
                       const u8 domain_sep[32], const u8 msg_hash[32]);

/* Confirms a dApp's connection request. Shows the origin (host) asking
 * for access to the GBA's address. Returns 1 if A (approve), 0 if B
 * (deny). The user only sees this screen the first time a given origin
 * asks to connect — afterwards the extension caches the decision. */
int confirm_connect_request(const char* origin, u32 origin_len);

/* "WIPE WALLET?" screen. Requires holding A for 3 seconds to confirm
 * (with a visible progress bar). Releasing A or pressing B/L/R/START
 * aborts the action. Returns 1 if the wipe was confirmed, 0 if it was
 * cancelled.
 *
 * Deliberately "annoying" design: a single accidental press must NOT
 * wipe the wallet. The hold gesture is muscle-memory enough to make it
 * a conscious action. */
int confirm_wipe_wallet(void);

#endif
