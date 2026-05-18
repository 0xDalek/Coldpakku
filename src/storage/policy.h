#ifndef STORAGE_POLICY_H
#define STORAGE_POLICY_H

#include "../types.h"

/*
 * Device policy persisted to SRAM. Lives in a SEPARATE slot from the
 * session blob (session.c uses offsets [0..117), policy uses offset
 * 1024) so it survives session_wipe() and can be configured even before
 * the seed is entered.
 *
 * SRAM layout at offset 1024:
 *
 *   [0..4)    magic "POLI"
 *   [4]       version 0x01
 *   [5]       reserved (0x00)
 *   [6..10)   active chain_id (u32 little-endian)   <- 0 = ANY (no lock)
 *   [10..14)  CRC32 over [0..10)
 *
 *   Total: 14 bytes.
 *
 * The real default (if there's no valid blob or the CRC fails) is
 * decided by the caller (state.c). Today: chain 1 (Ethereum mainnet).
 */

#define POLICY_BLOB_OFFSET   1024
#define POLICY_BLOB_SIZE     14
#define POLICY_MAGIC         "POLI"
#define POLICY_VERSION       0x01

/* Reads the policy from SRAM. If there is no valid blob, returns 0 and
 * *out_chain_id is left intact (caller sets its default). Returns 1 if
 * the blob existed. */
int policy_load(u32* out_chain_id);

/* Saves chain_id to SRAM. Returns 1 if OK. SRAM on the GBA is
 * battery-backed (not flash) so it can be overwritten as many times as
 * you want with no wear. */
int policy_save(u32 chain_id);

/* Wipes the policy slot (leaves 0xFF). */
void policy_wipe(void);

#endif
