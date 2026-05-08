#include "bip39.h"
#include "pbkdf2.h"
#include "../bip39_wordlist.h"
#include "sha256.h"

#include <string.h>

int bip39_word_index(const char* word) {
    int lo = 0, hi = BIP39_WORDLIST_LEN - 1;
    while (lo <= hi) {
        int mid = (lo + hi) >> 1;
        int cmp = strcmp(word, BIP39_WORDS[mid]);
        if (cmp == 0) return mid;
        if (cmp < 0) hi = mid - 1; else lo = mid + 1;
    }
    return -1;
}

u32 bip39_filter_prefix(const char* prefix, u32 max_out, u16* out_idx) {
    u32 plen = strlen(prefix);
    if (plen == 0) return 0;
    /* binary search del primer match */
    int lo = 0, hi = BIP39_WORDLIST_LEN;
    while (lo < hi) {
        int mid = (lo + hi) >> 1;
        if (strncmp(BIP39_WORDS[mid], prefix, plen) < 0) lo = mid + 1;
        else hi = mid;
    }
    u32 count = 0, written = 0;
    for (int i = lo; i < BIP39_WORDLIST_LEN; i++) {
        if (strncmp(BIP39_WORDS[i], prefix, plen) != 0) break;
        if (written < max_out) out_idx[written++] = (u16)i;
        count++;
    }
    return count;
}

int bip39_has_prefix(const char* prefix) {
    u32 plen = strlen(prefix);
    if (plen == 0) return 1;
    /* misma binary search; sin recorrido lineal posterior, asi es O(log N)
     * total y no O(log N + matches). Critico para el keyboard que llama
     * esto hasta 26 veces por pulsacion de UP/DOWN. */
    int lo = 0, hi = BIP39_WORDLIST_LEN;
    while (lo < hi) {
        int mid = (lo + hi) >> 1;
        if (strncmp(BIP39_WORDS[mid], prefix, plen) < 0) lo = mid + 1;
        else hi = mid;
    }
    if (lo >= BIP39_WORDLIST_LEN) return 0;
    return strncmp(BIP39_WORDS[lo], prefix, plen) == 0;
}

int bip39_validate_words(const u16 word_idx[BIP39_WORDS_COUNT]) {
    /* 12 palabras = 132 bits = 16.5 bytes
       Empaquetamos los 132 bits en un buffer de 17 bytes (último byte tiene
       solo 4 bits útiles en MSB). Entropy = primeros 16 bytes. Checksum =
       SHA256(entropy)[0] >> 4 == último nibble del bit 132. */
    u8 buf[17] = {0};
    int bit = 0;
    for (int i = 0; i < BIP39_WORDS_COUNT; i++) {
        u16 w = word_idx[i] & 0x07FF;   /* 11 bits */
        for (int b = 10; b >= 0; b--) {
            if (w & (1u << b)) buf[bit >> 3] |= (u8)(0x80 >> (bit & 7));
            bit++;
        }
    }
    u8 hash[32];
    SHA256_CTX s;
    sha256_init(&s);
    sha256_update(&s, buf, 16);
    sha256_final(&s, hash);

    u8 cs_expected = (hash[0] >> 4) & 0x0F;
    u8 cs_actual = (buf[16] >> 4) & 0x0F;
    return cs_expected == cs_actual;
}

u32 bip39_build_mnemonic(const u16 word_idx[BIP39_WORDS_COUNT],
                         char out[BIP39_MNEMONIC_MAX_LEN]) {
    u32 j = 0;
    for (int i = 0; i < BIP39_WORDS_COUNT; i++) {
        const char* w = BIP39_WORDS[word_idx[i]];
        u32 wl = strlen(w);
        memcpy(out + j, w, wl);
        j += wl;
        if (i + 1 < BIP39_WORDS_COUNT) out[j++] = ' ';
    }
    return j;
}

void bip39_mnemonic_to_seed(const char* mnemonic, u32 mlen,
                            const char* passphrase, u32 plen,
                            u8 seed[64],
                            pbkdf2_progress_fn progress, void* ud) {
    /* salt = "mnemonic" + passphrase, codificado UTF-8 NFKD.
       Asumimos passphrase ASCII; si es vacío plen=0 y no se concatena. */
    u8 salt[8 + 256];
    static const char prefix[8] = {'m','n','e','m','o','n','i','c'};
    memcpy(salt, prefix, 8);
    if (plen > 256) plen = 256;
    if (plen) memcpy(salt + 8, passphrase, plen);

    pbkdf2_hmac_sha512_64((const u8*)mnemonic, mlen,
                          salt, 8 + plen,
                          2048,
                          seed,
                          progress, ud);
}
