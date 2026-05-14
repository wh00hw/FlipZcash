/**
 * Sealed wallet storage for FlipZcash (audit H-5).
 *
 * Replaces the legacy RC4 wallet.dat with PIN-derived AEAD (AES-256-CTR
 * + HMAC-SHA256) provided by libzcash-orchard-c. See flipz_secure.h.
 */

#include "flipz_secure.h"
#include <storage/storage.h>
#include <aead.h>            /* libzcash-orchard-c: PIN KDF + AEAD seal/unseal */
#include <wallet_lockout.h>  /* libzcash-orchard-c: pure-data lockout state */
#include <rand.h>            /* random_buffer */
#include <memzero.h>
#include <string.h>

/* Flipper Zero firmware does not export flipz_strnlen via its FAP API surface.
 * Local replacement: bounded scan up to `cap`, returning the C-string
 * length or `cap` if no NUL is found within the limit. */
static inline size_t flipz_strnlen(const char* s, size_t cap) {
    size_t n = 0;
    while(n < cap && s[n] != '\0') n++;
    return n;
}

#define APP_DIR        "/ext/apps_data/flipz"
#define SEALED_PATH    APP_DIR "/wallet.sealed"
#define LOCKOUT_PATH   APP_DIR "/wallet.lockout"

#define MAGIC          "ZS01"
#define MAGIC_LEN      4
#define HEADER_LEN     (MAGIC_LEN + 16 + AEAD_NONCE_SIZE + AEAD_TAG_SIZE + 2)
/*                       4    +  salt + nonce         + tag           + ct_len_le */

#define MAX_SEALED_CT  240
#define SEALED_FILE_MAX (HEADER_LEN + MAX_SEALED_CT)

#define AAD            (const uint8_t*)"flipz mnemonic v1"
#define AAD_LEN        17

/* ------------------------------------------------------------------ */
/*  Low-level storage I/O                                              */
/* ------------------------------------------------------------------ */

static bool ensure_dir(void) {
    Storage* fs = furi_record_open(RECORD_STORAGE);
    storage_simply_mkdir(fs, APP_DIR);
    furi_record_close(RECORD_STORAGE);
    return true;
}

static bool file_write_all(const char* path, const uint8_t* data, size_t len) {
    Storage* fs = furi_record_open(RECORD_STORAGE);
    File* f = storage_file_alloc(fs);
    bool ok = false;
    if(storage_file_open(f, path, FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
        if(storage_file_write(f, data, len) == len) ok = true;
    }
    storage_file_close(f);
    storage_file_free(f);
    furi_record_close(RECORD_STORAGE);
    return ok;
}

static bool file_read_all(const char* path, uint8_t* data, size_t cap, size_t* out_len) {
    Storage* fs = furi_record_open(RECORD_STORAGE);
    File* f = storage_file_alloc(fs);
    bool ok = false;
    if(storage_file_open(f, path, FSAM_READ, FSOM_OPEN_EXISTING)) {
        size_t got = storage_file_read(f, data, cap);
        if(got > 0) { *out_len = got; ok = true; }
    }
    storage_file_close(f);
    storage_file_free(f);
    furi_record_close(RECORD_STORAGE);
    return ok;
}

static bool file_remove(const char* path) {
    Storage* fs = furi_record_open(RECORD_STORAGE);
    bool ok = storage_simply_remove(fs, path);
    furi_record_close(RECORD_STORAGE);
    return ok;
}

/* ------------------------------------------------------------------ */
/*  Lockout state on disk                                              */
/* ------------------------------------------------------------------ */

static void lockout_load(wallet_lockout_state_t* s) {
    uint8_t blob[WALLET_LOCKOUT_STATE_SIZE];
    size_t got = 0;
    if(file_read_all(LOCKOUT_PATH, blob, sizeof(blob), &got) &&
       got == WALLET_LOCKOUT_STATE_SIZE) {
        if(wallet_lockout_deserialize(s, blob)) return;
    }
    wallet_lockout_init(s);
}

static bool lockout_save(const wallet_lockout_state_t* s) {
    uint8_t blob[WALLET_LOCKOUT_STATE_SIZE];
    wallet_lockout_serialize(s, blob);
    return file_write_all(LOCKOUT_PATH, blob, sizeof(blob));
}

/* ------------------------------------------------------------------ */
/*  Public API                                                         */
/* ------------------------------------------------------------------ */

bool flipz_secure_wallet_exists(void) {
    Storage* fs = furi_record_open(RECORD_STORAGE);
    bool ok = storage_file_exists(fs, SEALED_PATH);
    furi_record_close(RECORD_STORAGE);
    return ok;
}

FlipzPinResult flipz_secure_provision(
    const char* mnemonic,
    const uint8_t pin[FLIPZ_PIN_LEN],
    const char* passphrase) {
    if(!mnemonic || !pin) return FLIPZ_PIN_INVALID_INPUT;

    /* Build the sealed file in a single buffer. The mnemonic + passphrase
     * are concatenated as `mnemonic\0passphrase\0` so unseal can split
     * them back. Up to MAX_SEALED_CT bytes total. */
    char pt_buf[MAX_SEALED_CT];
    memzero(pt_buf, sizeof(pt_buf));
    size_t mn_len = flipz_strnlen(mnemonic, MAX_SEALED_CT - 2);
    if(mn_len == 0) return FLIPZ_PIN_INVALID_INPUT;
    memcpy(pt_buf, mnemonic, mn_len);
    pt_buf[mn_len] = 0;
    size_t pp_len = passphrase ? flipz_strnlen(passphrase, MAX_SEALED_CT - mn_len - 2) : 0;
    if(mn_len + 1 + pp_len + 1 > MAX_SEALED_CT) return FLIPZ_PIN_INVALID_INPUT;
    if(pp_len > 0) memcpy(pt_buf + mn_len + 1, passphrase, pp_len);
    size_t pt_len = mn_len + 1 + pp_len + 1;

    uint8_t salt[16];
    uint8_t nonce[AEAD_NONCE_SIZE];
    random_buffer(salt, sizeof(salt));
    random_buffer(nonce, sizeof(nonce));

    uint8_t key[AEAD_KEY_SIZE];
    wallet_pin_kdf(pin, FLIPZ_PIN_LEN, salt, sizeof(salt),
                   FLIPZ_PIN_KDF_ITERATIONS, key);

    uint8_t tag[AEAD_TAG_SIZE];
    aead_aes256_ctr_hmac_seal(key, nonce, AAD, AAD_LEN,
                               (const uint8_t*)pt_buf, pt_len,
                               (uint8_t*)pt_buf, tag);  /* in-place encrypt */

    /* Compose the file. */
    uint8_t file_buf[SEALED_FILE_MAX];
    memzero(file_buf, sizeof(file_buf));
    size_t off = 0;
    memcpy(file_buf + off, MAGIC, MAGIC_LEN);          off += MAGIC_LEN;
    memcpy(file_buf + off, salt, sizeof(salt));        off += sizeof(salt);
    memcpy(file_buf + off, nonce, sizeof(nonce));      off += sizeof(nonce);
    memcpy(file_buf + off, tag, sizeof(tag));          off += sizeof(tag);
    file_buf[off++] = (uint8_t)(pt_len & 0xFF);
    file_buf[off++] = (uint8_t)((pt_len >> 8) & 0xFF);
    memcpy(file_buf + off, pt_buf, pt_len);            off += pt_len;

    ensure_dir();
    bool ok = file_write_all(SEALED_PATH, file_buf, off);

    wallet_lockout_state_t lo; wallet_lockout_init(&lo);
    lockout_save(&lo);

    memzero(pt_buf, sizeof(pt_buf));
    memzero(file_buf, sizeof(file_buf));
    memzero(salt, sizeof(salt));
    memzero(nonce, sizeof(nonce));
    memzero(key, sizeof(key));
    memzero(tag, sizeof(tag));

    return ok ? FLIPZ_PIN_OK : FLIPZ_PIN_IO_ERROR;
}

FlipzPinResult flipz_secure_unlock(
    const uint8_t pin[FLIPZ_PIN_LEN],
    char* mnemonic_out,
    size_t mnemonic_buf_len) {
    if(!pin || !mnemonic_out || mnemonic_buf_len < 256) {
        return FLIPZ_PIN_INVALID_INPUT;
    }

    /* Lockout pre-check. */
    wallet_lockout_state_t lo;
    lockout_load(&lo);
    if(wallet_lockout_should_wipe(&lo, FLIPZ_PIN_LOCKOUT_MAX)) {
        return FLIPZ_PIN_LOCKED_OUT;
    }

    if(!flipz_secure_wallet_exists()) return FLIPZ_PIN_NOT_INITIALIZED;

    uint8_t file_buf[SEALED_FILE_MAX];
    size_t got = 0;
    if(!file_read_all(SEALED_PATH, file_buf, sizeof(file_buf), &got)) {
        return FLIPZ_PIN_IO_ERROR;
    }
    if(got < HEADER_LEN || memcmp(file_buf, MAGIC, MAGIC_LEN) != 0) {
        memzero(file_buf, sizeof(file_buf));
        return FLIPZ_PIN_IO_ERROR;
    }

    size_t off = MAGIC_LEN;
    const uint8_t* salt  = file_buf + off; off += 16;
    const uint8_t* nonce = file_buf + off; off += AEAD_NONCE_SIZE;
    const uint8_t* tag   = file_buf + off; off += AEAD_TAG_SIZE;
    size_t ct_len = (size_t)file_buf[off] | ((size_t)file_buf[off + 1] << 8);
    off += 2;
    if(off + ct_len > got || ct_len > MAX_SEALED_CT) {
        memzero(file_buf, sizeof(file_buf));
        return FLIPZ_PIN_IO_ERROR;
    }
    const uint8_t* ct = file_buf + off;

    uint8_t key[AEAD_KEY_SIZE];
    wallet_pin_kdf(pin, FLIPZ_PIN_LEN, salt, 16,
                   FLIPZ_PIN_KDF_ITERATIONS, key);

    uint8_t pt[MAX_SEALED_CT];
    int rc = aead_aes256_ctr_hmac_unseal(key, nonce, AAD, AAD_LEN,
                                          ct, ct_len, tag, pt);
    memzero(key, sizeof(key));
    memzero(file_buf, sizeof(file_buf));

    if(rc != 0) {
        wallet_lockout_record_failure(&lo, 0);
        lockout_save(&lo);
        memzero(pt, sizeof(pt));
        if(wallet_lockout_should_wipe(&lo, FLIPZ_PIN_LOCKOUT_MAX)) {
            return FLIPZ_PIN_LOCKED_OUT;
        }
        return FLIPZ_PIN_WRONG;
    }

    /* Split pt into mnemonic + passphrase. (Passphrase is currently
     * unused on Flipper; reserved for the next UI revision.) */
    size_t mn_len = flipz_strnlen((char*)pt, ct_len);
    if(mn_len + 1 > mnemonic_buf_len) {
        memzero(pt, sizeof(pt));
        return FLIPZ_PIN_INVALID_INPUT;
    }
    memcpy(mnemonic_out, pt, mn_len);
    mnemonic_out[mn_len] = 0;
    memzero(pt, sizeof(pt));

    wallet_lockout_record_success(&lo);
    lockout_save(&lo);
    return FLIPZ_PIN_OK;
}

void flipz_secure_wipe(void) {
    file_remove(SEALED_PATH);
    file_remove(LOCKOUT_PATH);
}
