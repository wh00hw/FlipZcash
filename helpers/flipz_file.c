#include "flipz_file.h"
#include <storage/storage.h>
#include <loader/loader.h>
#include "../helpers/flipz_string.h"
#include <memzero.h>
#include <rand.h>
#include <string.h>

#define APP_DIR EXT_PATH("apps_data/flipz")
#define WALLET_PATH APP_DIR "/wallet.dat"
#define WALLET_BAK_PATH APP_DIR "/wallet.dat.bak"

// --- Wallet.dat layout (fixed-size blob) ---
// Offset  Len   Content
// 0       4     Magic "FZ01"
// 4       260   K2 section: "fb01" + 256 hex (K2 encrypted with K1)
// 264     516   Mnemonic section: "fb01" + 512 hex (mnemonic encrypted with K2)
// 780     256   Mainnet keys hex (ask+ak+nk+rivk)
// 1036    256   Testnet keys hex (ask+ak+nk+rivk)
// 1292    1     Testnet flag '0' or '1'
#define W_MAGIC     "FZ01"
#define W_MAGIC_LEN 4
#define W_K2_OFF    4
#define W_K2_LEN    260 // "fb01" + 256 hex
#define W_DAT_OFF   264
#define W_DAT_LEN   516 // "fb01" + 512 hex
#define W_KMAIN_OFF 780
#define W_KTEST_OFF 1036
#define W_KEYS_LEN  256
#define W_NET_OFF   1292
#define W_FILE_SIZE 1293

#define HLEN 4
#define KLEN 256
#define SLEN 512
static const char* HSTR = "fb01";
static const char* K1_HEX =
    "fb0131d5cf688221c109163908ebe51debb46227c6cc8b37641910833222772a"
    "baefe6d9ceb651842260e0d1e05e3b90d15e7d5ffaaabc0207bf200a117793a2";

static const char* TEXT_QRFILE = "Filetype: QRCode\n"
                                 "Version: 0\n"
                                 "Message: ";

// ============================================================
// Simple file helpers
// ============================================================

static const char* file_path(const char* name, char* buf, size_t buf_len) {
    snprintf(buf, buf_len, APP_DIR "/%s", name);
    return buf;
}

bool flipz_file_exists(const char* file_name) {
    char path[48];
    file_path(file_name, path, sizeof(path));
    Storage* fs = furi_record_open(RECORD_STORAGE);
    bool ret = storage_file_exists(fs, path);
    furi_record_close(RECORD_STORAGE);
    return ret;
}

bool flipz_file_delete(const char* file_name) {
    char path[48];
    file_path(file_name, path, sizeof(path));
    Storage* fs = furi_record_open(RECORD_STORAGE);
    bool ret = storage_simply_remove(fs, path);
    furi_record_close(RECORD_STORAGE);
    return ret;
}

bool flipz_file_read(const char* file_name, char* buf, size_t buf_len) {
    char path[48];
    file_path(file_name, path, sizeof(path));
    memzero(buf, buf_len);

    Storage* fs = furi_record_open(RECORD_STORAGE);
    File* f = storage_file_alloc(fs);
    bool ret = false;
    if(storage_file_open(f, path, FSAM_READ, FSOM_OPEN_EXISTING)) {
        char chr;
        size_t i = 0;
        while(storage_file_read(f, &chr, 1) == 1 && !storage_file_eof(f) && chr != '\n' &&
              chr != '\r') {
            if(i < buf_len - 1) buf[i] = chr;
            i++;
        }
        ret = (i > 0);
    }
    storage_file_close(f);
    storage_file_free(f);
    furi_record_close(RECORD_STORAGE);
    return ret;
}

bool flipz_file_write(const char* file_name, const char* data) {
    char path[48];
    file_path(file_name, path, sizeof(path));

    Storage* fs = furi_record_open(RECORD_STORAGE);
    storage_simply_mkdir(fs, APP_DIR);
    File* f = storage_file_alloc(fs);
    bool ret = false;
    if(storage_file_open(f, path, FSAM_WRITE, FSOM_OPEN_ALWAYS)) {
        storage_file_write(f, data, strlen(data));
        storage_file_write(f, "\n", 1);
        ret = true;
    }
    storage_file_close(f);
    storage_file_free(f);
    furi_record_close(RECORD_STORAGE);
    return ret;
}

bool flipz_save_qrfile(
    const char* qr_msg_prefix,
    const char* qr_msg_content,
    const char* file_name) {
    char buf[200] = {0};
    snprintf(buf, sizeof(buf), "%s%s%s", TEXT_QRFILE, qr_msg_prefix, qr_msg_content);
    return flipz_file_write(file_name, buf);
}

// ============================================================
// Wallet.dat raw I/O
// ============================================================

static bool wallet_raw_read(char* buf) {
    Storage* fs = furi_record_open(RECORD_STORAGE);
    File* f = storage_file_alloc(fs);
    bool ret = false;
    /* Zero buf BEFORE the read. Callers (wallet_save_mnemonic etc.) malloc
     * w without initialising it; on a partial-size migration the trailing
     * bytes used to be uninitialised garbage and get persisted back to
     * disk in the migration branch below. */
    memzero(buf, W_FILE_SIZE);
    if(storage_file_open(f, WALLET_PATH, FSAM_READ, FSOM_OPEN_EXISTING)) {
        uint16_t bytes_read = storage_file_read(f, buf, W_FILE_SIZE);
        if(bytes_read == W_FILE_SIZE) {
            if(memcmp(buf, W_MAGIC, W_MAGIC_LEN) == 0) {
                ret = true;
            }
        } else if(
            bytes_read >= (uint16_t)W_DAT_OFF + W_DAT_LEN &&
            memcmp(buf, W_MAGIC, W_MAGIC_LEN) == 0) {
            // Migration from older/smaller wallet.dat. buf is zero-initialised
            // above, so trailing-byte garbage is no longer persisted.
            buf[W_NET_OFF] = '0'; // default mainnet
            storage_file_close(f);
            storage_file_free(f);
            File* fw = storage_file_alloc(fs);
            if(storage_file_open(fw, WALLET_PATH, FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
                storage_file_write(fw, buf, W_FILE_SIZE);
            }
            storage_file_close(fw);
            storage_file_free(fw);
            furi_record_close(RECORD_STORAGE);
            return true;
        }
    }
    if(!ret) memzero(buf, W_FILE_SIZE);
    storage_file_close(f);
    storage_file_free(f);
    furi_record_close(RECORD_STORAGE);
    return ret;
}

static bool wallet_raw_write(const char* buf) {
    Storage* fs = furi_record_open(RECORD_STORAGE);
    storage_simply_mkdir(fs, APP_DIR);
    bool ret = false;

    File* f = storage_file_alloc(fs);
    if(storage_file_open(f, WALLET_PATH, FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
        if(storage_file_write(f, buf, W_FILE_SIZE) == W_FILE_SIZE) {
            ret = true;
        }
    }
    storage_file_close(f);
    storage_file_free(f);

    if(ret) {
        File* fb = storage_file_alloc(fs);
        if(storage_file_open(fb, WALLET_BAK_PATH, FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
            storage_file_write(fb, buf, W_FILE_SIZE);
        }
        storage_file_close(fb);
        storage_file_free(fb);
    }

    furi_record_close(RECORD_STORAGE);
    return ret;
}

static bool wallet_raw_read_safe(char* buf) {
    if(wallet_raw_read(buf)) return true;
    Storage* fs = furi_record_open(RECORD_STORAGE);
    File* f = storage_file_alloc(fs);
    bool ret = false;
    if(storage_file_open(f, WALLET_BAK_PATH, FSAM_READ, FSOM_OPEN_EXISTING)) {
        if(storage_file_read(f, buf, W_FILE_SIZE) == W_FILE_SIZE) {
            if(memcmp(buf, W_MAGIC, W_MAGIC_LEN) == 0) {
                ret = true;
            }
        }
    }
    if(!ret) memzero(buf, W_FILE_SIZE);
    storage_file_close(f);
    storage_file_free(f);
    furi_record_close(RECORD_STORAGE);
    return ret;
}

// ============================================================
// Wallet API
// ============================================================

bool wallet_exists(void) {
    Storage* fs = furi_record_open(RECORD_STORAGE);
    bool ret = storage_file_exists(fs, WALLET_PATH);
    furi_record_close(RECORD_STORAGE);
    return ret;
}

bool wallet_delete(void) {
    Storage* fs = furi_record_open(RECORD_STORAGE);
    storage_simply_remove(fs, WALLET_PATH);
    storage_simply_remove(fs, WALLET_BAK_PATH);
    furi_record_close(RECORD_STORAGE);
    return true;
}

bool wallet_save_mnemonic(const char* mnemonic) {
    char* w = malloc(W_FILE_SIZE);
    if(!w) return false;
    if(!wallet_raw_read_safe(w)) {
        memzero(w, W_FILE_SIZE);
        memcpy(w, W_MAGIC, W_MAGIC_LEN);
        w[W_NET_OFF] = '1'; // default testnet (debug build / dev work)
    }

    uint8_t k1[64];
    flipz_xtob(K1_HEX, k1, strlen(K1_HEX) / 2);

    uint8_t k2[128];
    random_buffer(k2, KLEN / 2);

    char* k2_sec = w + W_K2_OFF;
    memcpy(k2_sec, HSTR, HLEN);
    flipz_btox(k2, KLEN / 2, k2_sec + HLEN);
    flipz_cipher(k1, strlen(K1_HEX) / 2, k2_sec + HLEN, k2_sec + HLEN, KLEN);

    char* dat_sec = w + W_DAT_OFF;
    memcpy(dat_sec, HSTR, HLEN);
    size_t mlen = strlen(mnemonic);
    if(mlen > SLEN / 2) mlen = SLEN / 2;
    memzero(dat_sec + HLEN, SLEN);
    flipz_btox((const uint8_t*)mnemonic, mlen, dat_sec + HLEN);
    flipz_cipher(k2, KLEN / 2, dat_sec + HLEN, dat_sec + HLEN, SLEN);

    bool ret = wallet_raw_write(w);

    memzero(k1, sizeof(k1));
    memzero(k2, sizeof(k2));
    memzero(w, W_FILE_SIZE);
    free(w);
    return ret;
}

bool wallet_load_mnemonic(char* mnemonic_out) {
    char* w = malloc(W_FILE_SIZE);
    if(!w) return false;
    if(!wallet_raw_read_safe(w)) {
        free(w);
        return false;
    }

    char* k2_sec = w + W_K2_OFF;
    if(memcmp(k2_sec, HSTR, HLEN) != 0) {
        memzero(w, W_FILE_SIZE);
        free(w);
        return false;
    }

    uint8_t k1[64];
    flipz_xtob(K1_HEX, k1, strlen(K1_HEX) / 2);
    flipz_cipher(k1, strlen(K1_HEX) / 2, k2_sec + HLEN, k2_sec + HLEN, KLEN);
    uint8_t k2[128];
    flipz_xtob(k2_sec + HLEN, k2, KLEN / 2);

    char* dat_sec = w + W_DAT_OFF;
    if(memcmp(dat_sec, HSTR, HLEN) != 0) {
        memzero(k1, sizeof(k1));
        memzero(k2, sizeof(k2));
        memzero(w, W_FILE_SIZE);
        free(w);
        return false;
    }

    flipz_cipher(k2, KLEN / 2, dat_sec + HLEN, dat_sec + HLEN, SLEN);
    flipz_xtob(dat_sec + HLEN, (uint8_t*)(dat_sec + HLEN), SLEN / 2);
    strcpy(mnemonic_out, dat_sec + HLEN);

    memzero(k1, sizeof(k1));
    memzero(k2, sizeof(k2));
    memzero(w, W_FILE_SIZE);
    free(w);
    return true;
}

bool wallet_save_keys(
    bool testnet,
    const uint8_t ask[32],
    const uint8_t ak[32],
    const uint8_t nk[32],
    const uint8_t rivk[32]) {
    char* w = malloc(W_FILE_SIZE);
    if(!w) return false;
    if(!wallet_raw_read_safe(w)) {
        /* Bootstrap a fresh wallet.dat skeleton if none exists yet, so a
         * caller that derives keys before persisting a mnemonic does not
         * silently fail. The empty K2/DAT sections (no "fb01" header) will
         * cause wallet_load_mnemonic() to refuse — correct: nothing to
         * load. mnemonic_save() called later will fill them in. */
        memzero(w, W_FILE_SIZE);
        memcpy(w, W_MAGIC, W_MAGIC_LEN);
        w[W_NET_OFF] = testnet ? '1' : '0';
    }

    char* dest = w + (testnet ? W_KTEST_OFF : W_KMAIN_OFF);
    flipz_btox(ask, 32, dest);
    flipz_btox(ak, 32, dest + 64);
    flipz_btox(nk, 32, dest + 128);
    flipz_btox(rivk, 32, dest + 192);

    bool ret = wallet_raw_write(w);
    memzero(w, W_FILE_SIZE);
    free(w);
    return ret;
}

bool wallet_load_keys(
    bool testnet,
    uint8_t ask[32],
    uint8_t ak[32],
    uint8_t nk[32],
    uint8_t rivk[32]) {
    char* w = malloc(W_FILE_SIZE);
    if(!w) return false;
    if(!wallet_raw_read_safe(w)) {
        free(w);
        return false;
    }

    const char* src = w + (testnet ? W_KTEST_OFF : W_KMAIN_OFF);

    bool all_zero = true;
    for(int i = 0; i < W_KEYS_LEN && all_zero; i++) {
        if(src[i] != 0 && src[i] != '0') all_zero = false;
    }
    if(all_zero) {
        memzero(w, W_FILE_SIZE);
        free(w);
        return false;
    }

    const uint8_t* keys_out[] = {ask, ak, nk, rivk};
    for(int k = 0; k < 4; k++) {
        for(int i = 0; i < 32; i++) {
            char hi = src[k * 64 + i * 2];
            char lo = src[k * 64 + i * 2 + 1];
            uint8_t h =
                (hi >= 'a') ? (hi - 'a' + 10) : (hi >= 'A') ? (hi - 'A' + 10) : (hi - '0');
            uint8_t l =
                (lo >= 'a') ? (lo - 'a' + 10) : (lo >= 'A') ? (lo - 'A' + 10) : (lo - '0');
            ((uint8_t*)keys_out[k])[i] = (h << 4) | l;
        }
    }

    memzero(w, W_FILE_SIZE);
    free(w);
    return true;
}

bool wallet_save_testnet(bool testnet) {
    char* w = malloc(W_FILE_SIZE);
    if(!w) return false;

    if(!wallet_raw_read_safe(w)) {
        memzero(w, W_FILE_SIZE);
        memcpy(w, W_MAGIC, W_MAGIC_LEN);
        memcpy(w + W_K2_OFF, HSTR, HLEN);
        memcpy(w + W_DAT_OFF, HSTR, HLEN);
    }

    w[W_NET_OFF] = testnet ? '1' : '0';
    bool ret = wallet_raw_write(w);
    memzero(w, W_FILE_SIZE);
    free(w);
    return ret;
}

bool wallet_load_testnet(void) {
    char* w = malloc(W_FILE_SIZE);
    if(!w) return true;        /* testnet default on OOM (debug build) */
    bool testnet = true;        /* testnet default on no-wallet (debug) */
    if(wallet_raw_read_safe(w)) {
        testnet = (w[W_NET_OFF] != '0');
    }
    memzero(w, W_FILE_SIZE);
    free(w);
    return testnet;
}
