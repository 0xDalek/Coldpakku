#include "policy.h"
#include "sram.h"

#include <string.h>

/* CRC32 in the zlib/PNG style (poly 0xEDB88320 reversed). Small and
 * sufficient to detect bit-rot in SRAM or corrupted blobs. Not
 * cryptographic, but the policy needs no authentication (no secrets). */
static u32 crc32(const u8* data, u32 len) {
    u32 crc = 0xFFFFFFFFu;
    for (u32 i = 0; i < len; i++) {
        crc ^= data[i];
        for (int b = 0; b < 8; b++) {
            u32 mask = -(crc & 1u);
            crc = (crc >> 1) ^ (0xEDB88320u & mask);
        }
    }
    return crc ^ 0xFFFFFFFFu;
}

static void put_u32_le(u8* p, u32 v) {
    p[0] = (u8)( v        & 0xFF);
    p[1] = (u8)((v >>  8) & 0xFF);
    p[2] = (u8)((v >> 16) & 0xFF);
    p[3] = (u8)((v >> 24) & 0xFF);
}

static u32 get_u32_le(const u8* p) {
    return (u32)p[0]
         | ((u32)p[1] <<  8)
         | ((u32)p[2] << 16)
         | ((u32)p[3] << 24);
}

int policy_load(u32* out_chain_id) {
    u8 blob[POLICY_BLOB_SIZE];
    sram_read(POLICY_BLOB_OFFSET, blob, sizeof(blob));

    if (memcmp(blob, POLICY_MAGIC, 4) != 0) return 0;
    if (blob[4] != POLICY_VERSION) return 0;

    u32 expected = crc32(blob, 10);
    u32 actual   = get_u32_le(blob + 10);
    if (expected != actual) return 0;

    if (out_chain_id) *out_chain_id = get_u32_le(blob + 6);
    return 1;
}

int policy_save(u32 chain_id) {
    u8 blob[POLICY_BLOB_SIZE];
    memcpy(blob, POLICY_MAGIC, 4);
    blob[4] = POLICY_VERSION;
    blob[5] = 0x00;
    put_u32_le(blob + 6, chain_id);
    u32 crc = crc32(blob, 10);
    put_u32_le(blob + 10, crc);

    sram_write(POLICY_BLOB_OFFSET, blob, sizeof(blob));

    /* Read-back verification: SRAM on a real cartridge can fail (drained
     * battery, dirty contacts). If the read-back doesn't match we return
     * an error and the caller can warn the user. */
    u8 verify[POLICY_BLOB_SIZE];
    sram_read(POLICY_BLOB_OFFSET, verify, sizeof(verify));
    if (memcmp(blob, verify, sizeof(blob)) != 0) return 0;
    return 1;
}

void policy_wipe(void) {
    u8 zeros[POLICY_BLOB_SIZE];
    memset(zeros, 0xFF, sizeof(zeros));
    sram_write(POLICY_BLOB_OFFSET, zeros, sizeof(zeros));
}
