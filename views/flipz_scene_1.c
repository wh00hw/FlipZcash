#include "../flipz.h"
#include <furi.h>
#include <furi_hal.h>
#include <input/input.h>
#include <gui/elements.h>
#include <storage/storage.h>
#include <loader/loader.h>
#include <string.h>
#include "../helpers/flipz_string.h"
#include "../helpers/flipz_file.h"
#include "../helpers/flipz_serial.h"
// From: lib/libzcash-orchard-c
#include <memzero.h>
#include <rand.h>
#include <bip39.h>
#include <orchard.h>
#include <pallas.h>
#include <blake2b.h>
#include <segwit_addr.h>
#include <redpallas.h>
#include <hwp.h>
#include <orchard_signer.h>
#include <zip244.h>
#include <bip32.h>
#include <secp256k1.h>
// From: lib/qrcode
#include <qrcodegen.h>
#include <stdio.h>

#define TAG "FlipZ"

#define DERIV_PURPOSE 44
#define DERIV_ACCOUNT 0
#define DERIV_CHANGE  0

#define MAX_TEXT_LEN 30
#define MAX_TEXT_BUF (MAX_TEXT_LEN + 1)
#define MAX_ADDR_BUF (128 + 1)

#define PAGE_LOADING    0
#define PAGE_ADDR_ZEC   1
#define PAGE_KEYS       3
#define PAGE_MNEMONIC   4
#define PAGE_FVK        5
#define PAGE_SERIAL     9
#define PAGE_SIGN_INIT  10
#define PAGE_SIGN_WAIT  6
#define PAGE_SIGN_ADDR  7
#define PAGE_SIGN_AMOUNT 11
#define PAGE_SIGN_NET_ERR 12
#define PAGE_SIGN_DONE  8

struct FlipZScene1 {
    View* view;
    FlipZScene1Callback callback;
    void* context;
    FuriThread* worker_thread;
};

typedef struct {
    int page;
    int view_mode;
    int strength;
    uint32_t coin_type;
    bool overwrite;
    bool mnemonic_only;
    CONFIDENTIAL const char* mnemonic;
    CONFIDENTIAL uint8_t seed[64];
    CONFIDENTIAL const char* ask_hex;
    CONFIDENTIAL const char* nk_hex;
    CONFIDENTIAL const char* rivk_hex;
    char* recv_address;
    int addr_subpage; // 0=QR, 1=text
    char* fvk_hex;
} FlipZScene1Model;

// Signing display state
static volatile int s_sign_page = 0;
static uint64_t s_sign_amount = 0;
static uint64_t s_sign_fee = 0;
static char s_sign_recipient[120];
static const char* s_coin_label = "ZEC";
static const char* s_net_err_msg = "";
static volatile bool s_sign_confirmed = false;
static volatile bool s_sign_cancelled = false;
static volatile bool s_sign_done = false;

// Mnemonic display
#define DISP_LINE_COUNT 6
static CONFIDENTIAL char s_disp_lines[DISP_LINE_COUNT][MAX_TEXT_BUF];

// Progress tracking
static volatile uint8_t s_progress_pct = 0;
static const char* s_progress_label = "";
static View* s_progress_view = NULL;

static uint8_t s_progress_offset = 0;
static uint8_t s_progress_scale = 100;

static void flipz_progress_cb(uint8_t pct, const char* label, void* ctx) {
    (void)ctx;
    uint8_t new_pct = s_progress_offset + (uint8_t)((uint32_t)pct * s_progress_scale / 100);
    bool changed = (new_pct >= s_progress_pct + 2) || (label != s_progress_label);
    s_progress_pct = new_pct;
    s_progress_label = label;
    if(changed && s_progress_view) {
        with_view_model(s_progress_view, FlipZScene1Model * model, { UNUSED(model); }, true);
    }
}

// Sinsemilla S-table lookup from SD card (64KB: 1024 points x 64 bytes each)
#define SINSEMILLA_S_PATH EXT_PATH("apps_data/flipz/sinsemilla_s.bin")
#define SINSEMILLA_S_FILE_SIZE (1024 * 64)

typedef struct {
    Storage* storage;
    File* file;
    bool ok;
} SinsemillaCtx;

static bool sinsemilla_sd_lookup(uint32_t index, uint8_t buf_out[64], void* ctx) {
    SinsemillaCtx* sc = (SinsemillaCtx*)ctx;
    if(!sc->ok || index >= 1024) return false;
    if(!storage_file_seek(sc->file, index * 64, true)) return false;
    return (storage_file_read(sc->file, buf_out, 64) == 64);
}

static SinsemillaCtx s_sinsemilla_ctx;

static void sinsemilla_lookup_init(void) {
    s_sinsemilla_ctx.storage = furi_record_open(RECORD_STORAGE);
    s_sinsemilla_ctx.file = storage_file_alloc(s_sinsemilla_ctx.storage);
    s_sinsemilla_ctx.ok =
        storage_file_open(
            s_sinsemilla_ctx.file, SINSEMILLA_S_PATH, FSAM_READ, FSOM_OPEN_EXISTING) &&
        (storage_file_size(s_sinsemilla_ctx.file) == SINSEMILLA_S_FILE_SIZE);
    if(s_sinsemilla_ctx.ok) {
        pallas_set_sinsemilla_lookup(sinsemilla_sd_lookup, &s_sinsemilla_ctx);
    }
}

static void sinsemilla_lookup_deinit(void) {
    pallas_set_sinsemilla_lookup(NULL, NULL);
    if(s_sinsemilla_ctx.ok) storage_file_close(s_sinsemilla_ctx.file);
    storage_file_free(s_sinsemilla_ctx.file);
    furi_record_close(RECORD_STORAGE);
    s_sinsemilla_ctx.ok = false;
}

#define RECEIVE_FILE_MAINNET "ua_mainnet_address.txt"
#define RECEIVE_FILE_TESTNET "ua_testnet_address.txt"

// Generate worker: does ALL heavy work on a background thread
typedef struct {
    int strength;
    uint32_t coin_type;
    bool overwrite;
    char passphrase[TEXT_BUFFER_SIZE];
    int view_mode;
    View* view;
} GenWorkerCtx;

static int32_t gen_worker_thread(void* ctx) {
    GenWorkerCtx* w = (GenWorkerCtx*)ctx;
    pallas_set_progress_cb(flipz_progress_cb, NULL);
    sinsemilla_lookup_init();

    s_progress_pct = 0;
    s_progress_label = "Loading wallet...";
    if(s_progress_view) {
        with_view_model(s_progress_view, FlipZScene1Model * model, { UNUSED(model); }, true);
    }

    // --- Step 1: Generate or load mnemonic ---
    char* mnemonic = malloc(TEXT_BUFFER_SIZE);
    if(!mnemonic) goto fail;
    memzero(mnemonic, TEXT_BUFFER_SIZE);

    bool just_generated = false;
    if(w->overwrite || !wallet_exists()) {
        if(w->overwrite) {
            wallet_delete();
            flipz_file_delete(RECEIVE_FILE_MAINNET);
            flipz_file_delete(RECEIVE_FILE_TESTNET);
        }
        int strength = w->strength;
        if(strength != 128 && strength != 192) strength = 256;
        const char* mnemonic_gen = mnemonic_generate(strength);
        if(!mnemonic_gen || !wallet_save_mnemonic(mnemonic_gen)) {
            if(mnemonic_gen) mnemonic_clear();
            free(mnemonic);
            goto fail_save;
        }
        strncpy(mnemonic, mnemonic_gen, TEXT_BUFFER_SIZE - 1);
        mnemonic_clear();
        just_generated = true;
    }

    if(!just_generated && !wallet_load_mnemonic(mnemonic)) {
        free(mnemonic);
        goto fail_load;
    }
    if(mnemonic_check(mnemonic) == 0) {
        memzero(mnemonic, TEXT_BUFFER_SIZE);
        free(mnemonic);
        goto fail_mnemonic;
    }

    // --- Step 2: PBKDF2 ---
    s_progress_pct = 5;
    s_progress_label = "Deriving seed...";
    if(s_progress_view) {
        with_view_model(s_progress_view, FlipZScene1Model * model, { UNUSED(model); }, true);
    }

    CONFIDENTIAL uint8_t seed[64];
    mnemonic_to_seed(mnemonic, w->passphrase, seed, 0);

    // --- Step 3: Derive and cache keys for both networks ---
    s_progress_pct = 15;
    s_progress_label = "Deriving keys...";
    if(s_progress_view) {
        with_view_model(s_progress_view, FlipZScene1Model * model, { UNUSED(model); }, true);
    }

    {
        static const uint32_t coins[] = {133, 1};
        static const uint32_t ctypes[] = {CoinTypeZECOrchard, CoinTypeZECOrchardTest};
        char* ask_hex = NULL;
        char* nk_hex = NULL;
        char* rivk_hex = NULL;

        for(int ci = 0; ci < 2; ci++) {
            CONFIDENTIAL uint8_t sk[32], ask[32], nk[32], rivk[32];
            uint8_t ak[32];
            orchard_derive_account_sk(seed, coins[ci], DERIV_ACCOUNT, sk);
            orchard_derive_keys(sk, ask, nk, rivk);
            redpallas_derive_ak(ask, ak);
            wallet_save_keys(ctypes[ci] == CoinTypeZECOrchardTest, ask, ak, nk, rivk);

            if(coins[ci] == 133) {
                const size_t hexlen = 65;
                ask_hex = malloc(hexlen);
                memzero(ask_hex, hexlen);
                flipz_btox(ask, 32, ask_hex);
                nk_hex = malloc(hexlen);
                memzero(nk_hex, hexlen);
                flipz_btox(nk, 32, nk_hex);
                rivk_hex = malloc(hexlen);
                memzero(rivk_hex, hexlen);
                flipz_btox(rivk, 32, rivk_hex);
            }
            memzero(sk, 32);
            memzero(ask, 32);
            memzero(nk, 32);
            memzero(rivk, 32);
            memzero(ak, 32);
        }

        with_view_model(
            w->view,
            FlipZScene1Model * model,
            {
                model->mnemonic = mnemonic;
                model->mnemonic_only = false;
                model->view_mode = w->view_mode;
                model->coin_type = w->coin_type;
                model->overwrite = w->overwrite;
                model->strength = w->strength;
                memcpy(model->seed, seed, 64);
                model->ask_hex = ask_hex;
                model->nk_hex = nk_hex;
                model->rivk_hex = rivk_hex;
                model->recv_address = malloc(MAX_ADDR_BUF);
                if(model->recv_address) memzero(model->recv_address, MAX_ADDR_BUF);
            },
            true);
    }
    memzero(seed, 64);

    if(w->view_mode == FlipZViewModeKeys) {
        with_view_model(
            w->view, FlipZScene1Model * model, { model->page = PAGE_KEYS; }, true);
        goto done;
    } else if(w->view_mode == FlipZViewModeMnemonic) {
        with_view_model(
            w->view, FlipZScene1Model * model, { model->page = PAGE_MNEMONIC; }, true);
        goto done;
    }

    // --- Step 4: Generate unified address (Sinsemilla) ---
    s_progress_pct = 20;
    s_progress_label = "Generating address...";
    s_progress_offset = 20;
    s_progress_scale = 80;

    {
        bool is_testnet = (w->coin_type == CoinTypeZECOrchardTest);
        uint32_t coin = is_testnet ? 1 : 133;
        const char* hrp = is_testnet ? "utest" : "u";
        CONFIDENTIAL uint8_t ua_seed[64];
        with_view_model(
            w->view,
            FlipZScene1Model * model,
            { memcpy(ua_seed, model->seed, 64); },
            false);

        char* ua_buf = malloc(256);
        if(ua_buf) {
            memzero(ua_buf, 256);
            uint8_t d_out[11], pkd_out[32];
            int ua_len = orchard_derive_unified_address(
                ua_seed, coin, DERIV_ACCOUNT, hrp, ua_buf, 256, d_out, pkd_out);

            if(ua_len > 0) {
                with_view_model(
                    w->view,
                    FlipZScene1Model * model,
                    {
                        if(model->recv_address)
                            strncpy(model->recv_address, ua_buf, MAX_ADDR_BUF - 1);
                    },
                    true);
                flipz_file_write(
                    is_testnet ? RECEIVE_FILE_TESTNET : RECEIVE_FILE_MAINNET, ua_buf);
            }
            free(ua_buf);
        }
        memzero(ua_seed, 64);
    }

    s_progress_pct = 100;
    s_progress_label = "Done!";
    s_progress_offset = 0;
    s_progress_scale = 100;
    with_view_model(
        w->view, FlipZScene1Model * model, { model->page = PAGE_ADDR_ZEC; }, true);
    goto done;

fail_save:
    with_view_model(
        w->view,
        FlipZScene1Model * model,
        {
            model->mnemonic_only = true;
            model->mnemonic = "ERROR:,Save error";
            model->page = PAGE_MNEMONIC;
        },
        true);
    goto done;
fail_load:
    with_view_model(
        w->view,
        FlipZScene1Model * model,
        {
            model->mnemonic_only = true;
            model->mnemonic = "ERROR:,Load error";
            model->page = PAGE_MNEMONIC;
        },
        true);
    goto done;
fail_mnemonic:
    with_view_model(
        w->view,
        FlipZScene1Model * model,
        {
            model->mnemonic_only = true;
            model->mnemonic = "ERROR:,Mnemonic check error";
            model->page = PAGE_MNEMONIC;
        },
        true);
    goto done;
fail:
    with_view_model(
        w->view,
        FlipZScene1Model * model,
        {
            model->mnemonic_only = true;
            model->mnemonic = "ERROR:,Out of memory";
            model->page = PAGE_MNEMONIC;
        },
        true);
done:
    sinsemilla_lookup_deinit();
    memzero(w->passphrase, TEXT_BUFFER_SIZE);
    free(w);
    return 0;
}

// Sign worker context
typedef struct {
    uint8_t ask[32];
    uint8_t ak[32];
    uint8_t nk[32];
    uint8_t rivk[32];
    uint8_t t_sk[32];     // Transparent BIP-32 spending key (v3)
    uint8_t t_pubkey[33]; // Transparent compressed pubkey (v3)
    bool testnet;
    View* view;
} SignWorkerCtx;

// Callback context for feeding serial bytes into HWP parser
typedef struct {
    HwpParser* parser;
    HwpFeedResult last_result;
} SerialParserCtx;

static void serial_parser_cb(uint8_t byte, void* ctx) {
    SerialParserCtx* spc = (SerialParserCtx*)ctx;
    if(spc->last_result == HWP_FEED_FRAME_READY || spc->last_result == HWP_FEED_CRC_ERROR) {
        return;
    }
    HwpFeedResult r = hwp_parser_feed(spc->parser, byte);
    if(r != HWP_FEED_INCOMPLETE) {
        spc->last_result = r;
    }
}

// Send an HWP frame over serial
static void hwp_send(uint8_t seq, uint8_t msg_type, const uint8_t* payload, uint16_t len) {
    uint8_t buf[HWP_MAX_FRAME];
    size_t frame_len = hwp_encode(buf, seq, msg_type, payload, len);
    flipz_serial_send_raw(buf, frame_len);
}

static void hwp_send_error(uint8_t seq, HwpErrorCode code, const char* msg) {
    uint8_t buf[HWP_MAX_FRAME];
    size_t frame_len = hwp_encode_error(buf, seq, code, msg);
    flipz_serial_send_raw(buf, frame_len);
}

// Worker thread: HWP v2 binary protocol for signing
static int32_t sign_worker_thread(void* ctx) {
    SignWorkerCtx* w = (SignWorkerCtx*)ctx;

    flipz_serial_init();

    HwpParser parser;
    hwp_parser_init(&parser);
    SerialParserCtx spc = {.parser = &parser, .last_result = HWP_FEED_INCOMPLETE};

    OrchardSignerCtx signer_ctx;
    orchard_signer_init(&signer_ctx);

    uint8_t seq = 0;
    bool connected = false;
    bool user_confirmed = false;

    // Send initial PING
    hwp_send(seq++, HWP_MSG_PING, NULL, 0);

    while(s_sign_page != 0) {
        uint32_t flags = furi_thread_flags_wait(1, FuriFlagWaitAny, connected ? 50 : 500);
        (void)flags;

        if(s_sign_page == 0) break;

        // Drain CDC and feed into parser
        spc.last_result = HWP_FEED_INCOMPLETE;
        size_t bytes_rx = flipz_serial_drain(serial_parser_cb, &spc);

        // Collect full frame across multiple USB packets
        if(bytes_rx > 0 && spc.last_result == HWP_FEED_INCOMPLETE) {
            for(int retry = 0; retry < 5 && spc.last_result == HWP_FEED_INCOMPLETE; retry++) {
                furi_delay_ms(5);
                flipz_serial_drain(serial_parser_cb, &spc);
            }
        }

        // Send PING only if idle
        if(!connected && bytes_rx == 0) {
            hwp_send(seq++, HWP_MSG_PING, NULL, 0);
        }

        if(spc.last_result == HWP_FEED_CRC_ERROR) {
            hwp_send_error(0, HWP_ERR_BAD_FRAME, "CRC mismatch");
            hwp_parser_init(&parser);
            continue;
        }
        if(spc.last_result != HWP_FEED_FRAME_READY) continue;

        // Frame received
        HwpFrame* f = &parser.frame;
        connected = true;

        // Version check: accept v1 and v2
        if(f->version != HWP_VERSION && f->version != 0x01) {
            hwp_send_error(f->seq, HWP_ERR_UNSUPPORTED_VER, "Unsupported protocol version");
            continue;
        }

        switch(f->type) {
        case HWP_MSG_PONG:
            break;

        case HWP_MSG_PING:
            hwp_send(f->seq, HWP_MSG_PONG, NULL, 0);
            if(user_confirmed) {
                // New session: reset signing and verification state
                user_confirmed = false;
                orchard_signer_reset(&signer_ctx);
                s_sign_page = PAGE_SIGN_WAIT;
                with_view_model(
                    w->view, FlipZScene1Model * model, { UNUSED(model); }, true);
            }
            break;

        case HWP_MSG_FVK_REQ: {
            // v2.1: parse coin_type from payload for network discrimination
            if(f->payload_len >= HWP_FVK_REQ_SIZE) {
                uint32_t req_coin = (uint32_t)f->payload[0] |
                                    ((uint32_t)f->payload[1] << 8) |
                                    ((uint32_t)f->payload[2] << 16) |
                                    ((uint32_t)f->payload[3] << 24);
                uint32_t device_coin = w->testnet ? 1u : 133u;
                if(req_coin != 0 && req_coin != device_coin) {
                    hwp_send_error(
                        f->seq,
                        HWP_ERR_NETWORK_MISMATCH,
                        w->testnet ? "Device is on testnet"
                                   : "Device is on mainnet");
                    s_net_err_msg = w->testnet
                        ? "Companion requested MAINNET"
                        : "Companion requested TESTNET";
                    s_sign_page = PAGE_SIGN_NET_ERR;
                    with_view_model(
                        w->view, FlipZScene1Model * model, { UNUSED(model); }, true);
                    for(int i = 0; i < 30 && s_sign_page != 0; i++) furi_delay_ms(100);
                    if(s_sign_page == 0) break;
                    s_sign_page = PAGE_SIGN_WAIT;
                    with_view_model(
                        w->view, FlipZScene1Model * model, { UNUSED(model); }, true);
                    break;
                }
                signer_ctx.coin_type = req_coin;
            }
            uint8_t payload[96];
            memcpy(payload, w->ak, 32);
            memcpy(payload + 32, w->nk, 32);
            memcpy(payload + 64, w->rivk, 32);
            hwp_send(f->seq, HWP_MSG_FVK_RSP, payload, 96);
            break;
        }

        case HWP_MSG_TX_OUTPUT: {
            // HWP v2: staged sighash verification via OrchardSignerCtx
            HwpTxOutput txo;
            if(!hwp_parse_tx_output(f->payload, f->payload_len, &txo)) {
                hwp_send_error(f->seq, HWP_ERR_BAD_FRAME, "Invalid TX_OUTPUT payload");
                break;
            }

            OrchardSignerError serr;
            if(txo.output_index == HWP_TX_META_INDEX) {
                // Transaction metadata (first message)
                serr = orchard_signer_feed_meta(
                    &signer_ctx, txo.output_data, txo.output_data_len, txo.total_outputs);
                if(serr == SIGNER_ERR_NETWORK_MISMATCH) {
                    hwp_send_error(f->seq, HWP_ERR_NETWORK_MISMATCH,
                        "TxMeta coin_type != session coin_type");
                    s_net_err_msg = "TX metadata network mismatch";
                    s_sign_page = PAGE_SIGN_NET_ERR;
                    with_view_model(
                        w->view, FlipZScene1Model * model, { UNUSED(model); }, true);
                    for(int i = 0; i < 30 && s_sign_page != 0; i++) furi_delay_ms(100);
                    if(s_sign_page == 0) break;
                    s_sign_page = PAGE_SIGN_WAIT;
                    with_view_model(
                        w->view, FlipZScene1Model * model, { UNUSED(model); }, true);
                    orchard_signer_reset(&signer_ctx);
                    break;
                } else if(serr != SIGNER_OK) {
                    hwp_send_error(f->seq, HWP_ERR_BAD_FRAME, "Bad TX metadata");
                    orchard_signer_reset(&signer_ctx);
                    break;
                }
            } else if(txo.output_index == txo.total_outputs) {
                // Sentinel: expected sighash for comparison
                if(txo.output_data_len != 32) {
                    hwp_send_error(f->seq, HWP_ERR_BAD_SIGHASH, "Bad sighash length");
                    orchard_signer_reset(&signer_ctx);
                    break;
                }
                serr = orchard_signer_verify(&signer_ctx, txo.output_data);
                if(serr == SIGNER_ERR_SIGHASH_MISMATCH) {
                    hwp_send_error(f->seq, HWP_ERR_SIGHASH_MISMATCH,
                        "Device sighash != companion sighash");
                    orchard_signer_reset(&signer_ctx);
                    break;
                } else if(serr != SIGNER_OK) {
                    hwp_send_error(f->seq, HWP_ERR_INVALID_STATE, "Verify failed");
                    orchard_signer_reset(&signer_ctx);
                    break;
                }
            } else {
                // Action data (index 0..N-1)
                serr = orchard_signer_feed_action(
                    &signer_ctx, txo.output_data, txo.output_data_len);
                if(serr != SIGNER_OK) {
                    hwp_send_error(f->seq, HWP_ERR_BAD_FRAME, "Bad action data");
                    orchard_signer_reset(&signer_ctx);
                    break;
                }
            }

            hwp_send(f->seq, HWP_MSG_TX_OUTPUT_ACK, NULL, 0);
            break;
        }

        case HWP_MSG_TX_TRANSPARENT_INPUT: {
            // v3: transparent digest verification — wire-identical to TX_OUTPUT framing
            if(f->payload_len < HWP_TX_OUTPUT_HEADER) {
                hwp_send_error(f->seq, HWP_ERR_BAD_FRAME, "Transparent input too short");
                break;
            }
            uint16_t input_index =
                (uint16_t)f->payload[0] | ((uint16_t)f->payload[1] << 8);
            uint16_t total_inputs =
                (uint16_t)f->payload[2] | ((uint16_t)f->payload[3] << 8);
            const uint8_t* t_data = f->payload + HWP_TX_OUTPUT_HEADER;
            uint16_t t_data_len = f->payload_len - HWP_TX_OUTPUT_HEADER;

            OrchardSignerError serr;

            // First input (and we are still in RECEIVING_ACTIONS) → begin session
            if(input_index == 0 && signer_ctx.state == SIGNER_RECEIVING_ACTIONS) {
                serr = orchard_signer_begin_transparent(&signer_ctx, total_inputs, 0);
                if(serr != SIGNER_OK) {
                    hwp_send_error(f->seq, HWP_ERR_INVALID_STATE,
                        "Cannot begin transparent");
                    orchard_signer_reset(&signer_ctx);
                    break;
                }
            }

            // Sentinel: index == total → verify transparent digest
            if(input_index == total_inputs) {
                if(t_data_len != 32) {
                    hwp_send_error(f->seq, HWP_ERR_BAD_FRAME,
                        "Transparent sentinel must be 32 bytes");
                    orchard_signer_reset(&signer_ctx);
                    break;
                }
                serr = orchard_signer_verify_transparent(&signer_ctx, t_data);
                if(serr == SIGNER_ERR_TRANSPARENT_MISMATCH) {
                    hwp_send_error(f->seq, HWP_ERR_TRANSPARENT_DIGEST_MISMATCH,
                        "Transparent digest mismatch");
                    break;
                } else if(serr != SIGNER_OK) {
                    hwp_send_error(f->seq, HWP_ERR_INVALID_STATE,
                        "Transparent verify failed");
                    orchard_signer_reset(&signer_ctx);
                    break;
                }
                hwp_send(f->seq, HWP_MSG_TX_OUTPUT_ACK, NULL, 0);
                break;
            }

            // Normal input data
            serr = orchard_signer_feed_transparent_input(
                &signer_ctx, t_data, t_data_len);
            if(serr != SIGNER_OK) {
                HwpErrorCode code = (serr == SIGNER_ERR_BAD_STATE)
                                        ? HWP_ERR_INVALID_STATE
                                        : HWP_ERR_BAD_FRAME;
                hwp_send_error(f->seq, code, "Bad transparent input");
                orchard_signer_reset(&signer_ctx);
                break;
            }
            hwp_send(f->seq, HWP_MSG_TX_OUTPUT_ACK, NULL, 0);
            break;
        }

        case HWP_MSG_TX_TRANSPARENT_OUTPUT: {
            // v3: transparent outputs for digest computation
            if(f->payload_len < HWP_TX_OUTPUT_HEADER) {
                hwp_send_error(f->seq, HWP_ERR_BAD_FRAME, "Transparent output too short");
                break;
            }
            uint16_t output_index =
                (uint16_t)f->payload[0] | ((uint16_t)f->payload[1] << 8);
            uint16_t total_outputs =
                (uint16_t)f->payload[2] | ((uint16_t)f->payload[3] << 8);
            const uint8_t* t_data = f->payload + HWP_TX_OUTPUT_HEADER;
            uint16_t t_data_len = f->payload_len - HWP_TX_OUTPUT_HEADER;

            // Lazy: first output carries total_outputs — set it on the signer
            if(output_index == 0 && signer_ctx.transparent_outputs_expected == 0) {
                signer_ctx.transparent_outputs_expected = total_outputs;
            }

            OrchardSignerError serr = orchard_signer_feed_transparent_output(
                &signer_ctx, t_data, t_data_len);
            if(serr != SIGNER_OK) {
                HwpErrorCode code = (serr == SIGNER_ERR_BAD_STATE)
                                        ? HWP_ERR_INVALID_STATE
                                        : HWP_ERR_BAD_FRAME;
                hwp_send_error(f->seq, code, "Bad transparent output");
                orchard_signer_reset(&signer_ctx);
                break;
            }
            hwp_send(f->seq, HWP_MSG_TX_OUTPUT_ACK, NULL, 0);
            break;
        }

        case HWP_MSG_TRANSPARENT_SIGN_REQ: {
            // v3: on-device ECDSA signing for transparent inputs
            if(f->payload_len < HWP_TX_OUTPUT_HEADER) {
                hwp_send_error(f->seq, HWP_ERR_BAD_FRAME, "Transparent sign req too short");
                break;
            }
            uint16_t input_index =
                (uint16_t)f->payload[0] | ((uint16_t)f->payload[1] << 8);
            const uint8_t* input_data = f->payload + HWP_TX_OUTPUT_HEADER;
            uint16_t input_data_len = f->payload_len - HWP_TX_OUTPUT_HEADER;

            if(!signer_ctx.transparent_verified) {
                hwp_send_error(f->seq, HWP_ERR_INVALID_STATE,
                    "Transparent not verified");
                break;
            }

            // Compute per-input sighash on-device (ZIP-244 S.2)
            uint8_t per_input_sighash[32];
            zip244_transparent_per_input_sighash(
                &signer_ctx.transparent_state,
                input_index,
                input_data,
                input_data_len,
                0x01, // SIGHASH_ALL
                per_input_sighash);

            // ECDSA sign with pre-derived transparent SK
            uint8_t compact_sig[64];
            if(secp256k1_ecdsa_sign_digest(w->t_sk, per_input_sighash, compact_sig) != 0) {
                memzero(per_input_sighash, sizeof(per_input_sighash));
                hwp_send_error(f->seq, HWP_ERR_SIGN_FAILED, "ECDSA sign failed");
                break;
            }

            // DER-encode: der_sig_len[1] || der_sig[N] || sighash_type[1] || pubkey[33]
            uint8_t der_sig[72];
            size_t der_len = secp256k1_sig_to_der(compact_sig, der_sig);
            memzero(compact_sig, sizeof(compact_sig));

            uint8_t rsp[HWP_TRANSPARENT_SIGN_RSP_MAX];
            rsp[0] = (uint8_t)der_len;
            memcpy(rsp + 1, der_sig, der_len);
            rsp[1 + der_len] = 0x01; // SIGHASH_ALL
            memcpy(rsp + 1 + der_len + 1, w->t_pubkey, 33);

            size_t rsp_len = 1 + der_len + 1 + 33;
            hwp_send(f->seq, HWP_MSG_TRANSPARENT_SIGN_RSP, rsp, (uint16_t)rsp_len);
            memzero(per_input_sighash, sizeof(per_input_sighash));
            break;
        }

        case HWP_MSG_SIGN_REQ: {
            HwpSignReq req;
            if(!hwp_parse_sign_req(f->payload, f->payload_len, &req)) {
                hwp_send_error(f->seq, HWP_ERR_BAD_SIGHASH, "Invalid SIGN_REQ payload");
                break;
            }

            // Enforce ZIP-244 verification before signing
            OrchardSignerError chk = orchard_signer_check(&signer_ctx, req.sighash);
            if(chk == SIGNER_ERR_NOT_VERIFIED) {
                hwp_send_error(f->seq, HWP_ERR_INVALID_STATE,
                    "ZIP-244 verification not completed");
                break;
            } else if(chk == SIGNER_ERR_WRONG_SIGHASH) {
                hwp_send_error(f->seq, HWP_ERR_SIGHASH_MISMATCH,
                    "SIGN_REQ sighash != verified sighash");
                break;
            } else if(chk != SIGNER_OK) {
                hwp_send_error(f->seq, HWP_ERR_INVALID_STATE, "Signer check failed");
                break;
            }

            // Validate network (only on first request of a session)
            if(!user_confirmed) {
                bool addr_is_testnet = (strncmp(req.recipient, "utest", 5) == 0);
                if(addr_is_testnet != w->testnet) {
                    hwp_send_error(
                        f->seq,
                        HWP_ERR_NETWORK_MISMATCH,
                        w->testnet ? "Mainnet addr on testnet signer"
                                   : "Testnet addr on mainnet signer");
                    s_net_err_msg = addr_is_testnet ? "Received TESTNET address"
                                                    : "Received MAINNET address";
                    s_sign_page = PAGE_SIGN_NET_ERR;
                    with_view_model(
                        w->view, FlipZScene1Model * model, { UNUSED(model); }, true);
                    for(int i = 0; i < 30 && s_sign_page != 0; i++) furi_delay_ms(100);
                    if(s_sign_page == 0) break;
                    s_sign_page = PAGE_SIGN_WAIT;
                    with_view_model(
                        w->view, FlipZScene1Model * model, { UNUSED(model); }, true);
                    break;
                }

                // Show confirmation UI
                s_sign_amount = req.amount;
                s_sign_fee = req.fee;
                strncpy(s_sign_recipient, req.recipient, sizeof(s_sign_recipient) - 1);
                s_sign_recipient[sizeof(s_sign_recipient) - 1] = '\0';
                s_sign_confirmed = false;
                s_sign_cancelled = false;
                s_sign_done = false;
                s_sign_page = PAGE_SIGN_ADDR;
                with_view_model(
                    w->view, FlipZScene1Model * model, { UNUSED(model); }, true);

                // Wait for user
                while(!s_sign_confirmed && !s_sign_cancelled && s_sign_page != 0) {
                    furi_delay_ms(100);
                }
                if(s_sign_page == 0) break;

                if(!s_sign_confirmed) {
                    hwp_send_error(f->seq, HWP_ERR_USER_CANCELLED, "User cancelled");
                    s_sign_page = PAGE_SIGN_WAIT;
                    with_view_model(
                        w->view, FlipZScene1Model * model, { UNUSED(model); }, true);
                    break;
                }

                user_confirmed = true;
            }

            // Sign via OrchardSignerCtx (enforces verification invariant)
            s_sign_page = PAGE_SIGN_DONE;
            s_sign_done = false;
            with_view_model(
                w->view, FlipZScene1Model * model, { UNUSED(model); }, true);

            pallas_set_progress_cb(flipz_progress_cb, NULL);
            uint8_t sig[64], rk[32];
            OrchardSignerError serr = orchard_signer_sign(
                &signer_ctx, req.sighash, w->ask, req.alpha, sig, rk);

            if(serr != SIGNER_OK) {
                hwp_send_error(f->seq, HWP_ERR_SIGN_FAILED, "RedPallas sign failed");
                s_sign_page = PAGE_SIGN_WAIT;
                with_view_model(
                    w->view, FlipZScene1Model * model, { UNUSED(model); }, true);
                break;
            }

            // Send SIGN_RSP: sig[64] || rk[32] = 96 bytes
            uint8_t rsp[96];
            memcpy(rsp, sig, 64);
            memcpy(rsp + 64, rk, 32);
            hwp_send(f->seq, HWP_MSG_SIGN_RSP, rsp, 96);

            s_sign_done = true;
            with_view_model(
                w->view, FlipZScene1Model * model, { UNUSED(model); }, true);
            break;
        }

        case HWP_MSG_ABORT:
            // Companion requested session abort
            s_sign_cancelled = true;
            user_confirmed = false;
            orchard_signer_reset(&signer_ctx);
            s_sign_page = PAGE_SIGN_WAIT;
            with_view_model(
                w->view, FlipZScene1Model * model, { UNUSED(model); }, true);
            break;

        default:
            hwp_send_error(f->seq, HWP_ERR_UNKNOWN, "Unknown message type");
            break;
        }
    }

    flipz_serial_deinit();
    memzero(w, sizeof(SignWorkerCtx));
    free(w);
    return 0;
}

void flipz_scene_1_set_callback(
    FlipZScene1* instance,
    FlipZScene1Callback callback,
    void* context) {
    furi_assert(instance);
    furi_assert(callback);
    instance->callback = callback;
    instance->context = context;
}

static void flipz_scene_1_draw_mnemonic(const char* mnemonic) {
    const size_t mnemonic_working_len = strlen(mnemonic) + 1;
    char* mnemonic_working = malloc(mnemonic_working_len);
    strcpy(mnemonic_working, mnemonic);
    int word = 0;
    for(size_t i = 0; i < strlen(mnemonic_working); i++) {
        if(mnemonic_working[i] == ' ') {
            word++;
            if(word % 4 == 0) {
                mnemonic_working[i] = ',';
            }
        }
    }

    char* mnemonic_part = flipz_strtok(mnemonic_working, ",");
    int mi = 0;
    while(mnemonic_part != NULL && mi < DISP_LINE_COUNT) {
        memzero(s_disp_lines[mi], MAX_TEXT_BUF);
        size_t plen = strlen(mnemonic_part);
        if(plen > MAX_TEXT_LEN) plen = MAX_TEXT_LEN;
        strncpy(s_disp_lines[mi], mnemonic_part, plen);
        mi++;
        mnemonic_part = flipz_strtok(NULL, ",");
    }

    memzero(mnemonic_working, mnemonic_working_len);
    free(mnemonic_working);
}

static void flipz_scene_1_clear_text() {
    memzero(s_disp_lines, sizeof(s_disp_lines));
}

void flipz_scene_1_draw(Canvas* canvas, FlipZScene1Model* model) {
    canvas_clear(canvas);
    canvas_set_color(canvas, ColorBlack);
    flipz_scene_1_clear_text();

    if(model->page == PAGE_LOADING) {
        canvas_set_font(canvas, FontPrimary);
        canvas_draw_str(canvas, 2, 10, "Generate address");
        canvas_set_font(canvas, FontSecondary);
        canvas_draw_str(canvas, 2, 24, s_progress_label);
        canvas_draw_frame(canvas, 2, 34, 124, 10);
        uint8_t fill = (uint8_t)((uint32_t)s_progress_pct * 120 / 100);
        if(fill > 0) canvas_draw_box(canvas, 4, 36, fill, 6);
        char pct_text[8];
        snprintf(pct_text, sizeof(pct_text), "%d%%", s_progress_pct);
        canvas_draw_str_aligned(canvas, 64, 52, AlignCenter, AlignTop, pct_text);

    } else if(model->page == PAGE_ADDR_ZEC) {
        const char* addr = model->recv_address;
        const char* label = (model->coin_type == CoinTypeZECOrchardTest)
                                ? "TAZ Address (Testnet)"
                                : "ZEC Address";

        if(addr && addr[0]) {
            size_t len = strlen(addr);

            if(model->addr_subpage == 0) {
                // QR code centered
                uint8_t qr_buf[qrcodegen_BUFFER_LEN_FOR_VERSION(6)];
                uint8_t tmp_buf[qrcodegen_BUFFER_LEN_FOR_VERSION(6)];
                bool qr_ok = qrcodegen_encodeText(
                    addr,
                    tmp_buf,
                    qr_buf,
                    qrcodegen_Ecc_LOW,
                    1,
                    6,
                    qrcodegen_Mask_AUTO,
                    true);

                if(qr_ok) {
                    int qr_size = qrcodegen_getSize(qr_buf);

                    canvas_set_font(canvas, FontSecondary);
                    canvas_draw_str_aligned(
                        canvas, 64, 6, AlignCenter, AlignCenter, label);

                    int qr_x = (128 - qr_size) / 2;
                    int qr_y = 12 + (52 - qr_size) / 2;

                    canvas_set_color(canvas, ColorBlack);
                    for(int y = 0; y < qr_size; y++) {
                        for(int x = 0; x < qr_size; x++) {
                            if(qrcodegen_getModule(qr_buf, x, y)) {
                                canvas_draw_dot(canvas, qr_x + x, qr_y + y);
                            }
                        }
                    }
                }

            } else {
                // Full address text centered
                canvas_set_font(canvas, FontSecondary);
                canvas_draw_str_aligned(
                    canvas, 64, 6, AlignCenter, AlignCenter, label);

                canvas_set_font(canvas, FontKeyboard);
                const int cpl = 21;
                int total_rows = ((int)len + cpl - 1) / cpl;
                int block_h = total_rows * 8;
                int y_start = 14 + (50 - block_h) / 2;

                char line[22];
                for(int row = 0; row < total_rows; row++) {
                    size_t off = (size_t)(row * cpl);
                    size_t n = len - off;
                    if(n > (size_t)cpl) n = (size_t)cpl;
                    memcpy(line, addr + off, n);
                    line[n] = '\0';
                    canvas_draw_str_aligned(
                        canvas, 64, y_start + row * 8, AlignCenter, AlignTop, line);
                }
            }
        } else {
            canvas_set_font(canvas, FontSecondary);
            canvas_draw_str_aligned(
                canvas, 64, 32, AlignCenter, AlignCenter, "No address");
        }

    } else if(model->page == PAGE_KEYS) {
        canvas_set_font(canvas, FontSecondary);
        canvas_draw_str(canvas, 1, 8, "ask (spending key):");
        canvas_draw_str(canvas, 1, 16, model->ask_hex ? model->ask_hex : "");
        canvas_draw_str(canvas, 1, 28, "nk (nullifier key):");
        canvas_draw_str(canvas, 1, 36, model->nk_hex ? model->nk_hex : "");
        canvas_draw_str(canvas, 1, 48, "rivk (commit rand):");
        canvas_draw_str(canvas, 1, 56, model->rivk_hex ? model->rivk_hex : "");

    } else if(model->page == PAGE_MNEMONIC) {
        flipz_scene_1_draw_mnemonic(model->mnemonic);
        canvas_set_font(canvas, FontSecondary);
        for(int i = 0; i < DISP_LINE_COUNT; i++) {
            canvas_draw_str_aligned(
                canvas, 1, 2 + i * 10, AlignLeft, AlignTop, s_disp_lines[i]);
        }

    } else if(model->page == PAGE_FVK) {
        canvas_set_font(canvas, FontSecondary);
        canvas_draw_str_aligned(
            canvas, 64, 6, AlignCenter, AlignCenter, "Full Viewing Key");
        if(model->fvk_hex) {
            canvas_set_font(canvas, FontKeyboard);
            size_t len = strlen(model->fvk_hex);
            const int cpl = 21;
            int total_rows = ((int)len + cpl - 1) / cpl;
            int block_h = total_rows * 8;
            int y_start = 14 + (50 - block_h) / 2;
            char line[22];
            for(int row = 0; row < total_rows && row < 6; row++) {
                size_t off = (size_t)(row * cpl);
                size_t n = len - off;
                if(n > (size_t)cpl) n = (size_t)cpl;
                memcpy(line, model->fvk_hex + off, n);
                line[n] = '\0';
                canvas_draw_str_aligned(
                    canvas, 64, y_start + row * 8, AlignCenter, AlignTop, line);
            }
        }

    } else if(s_sign_page == PAGE_SIGN_INIT) {
        canvas_set_font(canvas, FontPrimary);
        canvas_draw_str_aligned(
            canvas, 64, 20, AlignCenter, AlignCenter, "Activating signer...");
        canvas_set_font(canvas, FontSecondary);
        canvas_draw_str_aligned(
            canvas, 64, 38, AlignCenter, AlignCenter, "Loading wallet, please wait");

    } else if(s_sign_page == PAGE_SIGN_WAIT) {
        canvas_set_font(canvas, FontPrimary);
        canvas_draw_str_aligned(
            canvas, 64, 16, AlignCenter, AlignCenter, "Serial listening...");
        canvas_set_font(canvas, FontSecondary);
        canvas_draw_str_aligned(
            canvas, 64, 34, AlignCenter, AlignCenter, "Awaiting commands from");
        canvas_draw_str_aligned(
            canvas, 64, 46, AlignCenter, AlignCenter, "companion broadcast app");

    } else if(s_sign_page == PAGE_SIGN_ADDR) {
        canvas_set_font(canvas, FontPrimary);
        canvas_draw_str_aligned(
            canvas, 64, 2, AlignCenter, AlignTop, "Recipient");
        canvas_set_font(canvas, FontSecondary);
        {
            const int chars_per_line = 25;
            const int y_start = 14;
            const int line_h = 9;
            const int max_lines = 5;
            size_t len = strlen(s_sign_recipient);
            for(int row = 0; row < max_lines && (size_t)(row * chars_per_line) < len; row++) {
                char line[26];
                size_t offset = row * chars_per_line;
                size_t n = len - offset;
                if(n > (size_t)chars_per_line) n = chars_per_line;
                memcpy(line, s_sign_recipient + offset, n);
                line[n] = '\0';
                canvas_draw_str_aligned(
                    canvas, 64, y_start + row * line_h, AlignCenter, AlignTop, line);
            }
        }
        canvas_draw_str_aligned(
            canvas, 64, 58, AlignCenter, AlignCenter, "[>] Continue  [<] Cancel");

    } else if(s_sign_page == PAGE_SIGN_AMOUNT) {
        canvas_set_font(canvas, FontPrimary);
        canvas_draw_str_aligned(
            canvas, 64, 4, AlignCenter, AlignTop, "Sign Transaction?");
        canvas_set_font(canvas, FontSecondary);
        char buf[32];
        snprintf(
            buf,
            sizeof(buf),
            "Send: %lu.%08lu %s",
            (unsigned long)(s_sign_amount / 100000000ULL),
            (unsigned long)(s_sign_amount % 100000000ULL),
            s_coin_label);
        canvas_draw_str_aligned(canvas, 64, 22, AlignCenter, AlignCenter, buf);
        snprintf(
            buf,
            sizeof(buf),
            "Fee: %lu.%08lu %s",
            (unsigned long)(s_sign_fee / 100000000ULL),
            (unsigned long)(s_sign_fee % 100000000ULL),
            s_coin_label);
        canvas_draw_str_aligned(canvas, 64, 36, AlignCenter, AlignCenter, buf);
        canvas_draw_str_aligned(
            canvas, 64, 58, AlignCenter, AlignCenter, "[OK] Sign  [<] Cancel");

    } else if(s_sign_page == PAGE_SIGN_NET_ERR) {
        canvas_set_font(canvas, FontPrimary);
        canvas_draw_str_aligned(
            canvas, 64, 12, AlignCenter, AlignCenter, "Network mismatch!");
        canvas_set_font(canvas, FontSecondary);
        canvas_draw_str_aligned(
            canvas, 64, 30, AlignCenter, AlignCenter, s_net_err_msg);
        char expected[32];
        snprintf(expected, sizeof(expected), "Signer is on %s", s_coin_label);
        canvas_draw_str_aligned(
            canvas, 64, 44, AlignCenter, AlignCenter, expected);

    } else if(s_sign_page == PAGE_SIGN_DONE) {
        canvas_set_font(canvas, FontPrimary);
        if(s_sign_done) {
            canvas_draw_str_aligned(
                canvas, 64, 24, AlignCenter, AlignCenter, "Signature sent!");
        } else {
            canvas_draw_str_aligned(
                canvas, 64, 24, AlignCenter, AlignCenter, "Signing...");
            canvas_set_font(canvas, FontSecondary);
            canvas_draw_str_aligned(
                canvas, 64, 40, AlignCenter, AlignCenter, s_progress_label);
        }
    }
}

bool flipz_scene_1_input(InputEvent* event, void* context) {
    furi_assert(context);
    FlipZScene1* instance = context;

    bool busy = false;
    with_view_model(
        instance->view,
        FlipZScene1Model * model,
        { busy = (model->page == PAGE_LOADING); },
        false);
    if(busy) return true;

    if(event->type == InputTypeRelease) {
        switch(event->key) {
        case InputKeyBack:
            with_view_model(
                instance->view,
                FlipZScene1Model * model,
                {
                    if(model->page == PAGE_SERIAL) {
                        s_sign_page = 0;
                        s_sign_cancelled = true;
                    }
                },
                false);
            instance->callback(FlipZCustomEventScene1Back, instance->context);
            break;
        case InputKeyRight:
            with_view_model(
                instance->view,
                FlipZScene1Model * model,
                {
                    if(model->page == PAGE_ADDR_ZEC) {
                        model->addr_subpage = 1;
                    } else if(s_sign_page == PAGE_SIGN_ADDR) {
                        s_sign_page = PAGE_SIGN_AMOUNT;
                    }
                },
                true);
            break;
        case InputKeyOk:
            with_view_model(
                instance->view,
                FlipZScene1Model * model,
                {
                    if(model->page == PAGE_ADDR_ZEC) {
                        model->addr_subpage = 1;
                    } else if(s_sign_page == PAGE_SIGN_AMOUNT) {
                        s_sign_confirmed = true;
                    }
                },
                true);
            break;
        case InputKeyLeft:
            with_view_model(
                instance->view,
                FlipZScene1Model * model,
                {
                    if(model->page == PAGE_ADDR_ZEC) {
                        model->addr_subpage = 0;
                    } else if(s_sign_page == PAGE_SIGN_ADDR) {
                        s_sign_cancelled = true;
                    } else if(s_sign_page == PAGE_SIGN_AMOUNT) {
                        s_sign_page = PAGE_SIGN_ADDR;
                    }
                },
                true);
            break;
        case InputKeyDown:
        case InputKeyUp:
            break;
        case InputKeyMAX:
            break;
        }
    }
    return true;
}

void flipz_scene_1_exit(void* context) {
    furi_assert(context);
    FlipZScene1* instance = (FlipZScene1*)context;

    if(instance->worker_thread) {
        furi_thread_join(instance->worker_thread);
        furi_thread_free(instance->worker_thread);
        instance->worker_thread = NULL;
    }

    with_view_model(
        instance->view,
        FlipZScene1Model * model,
        {
            model->page = PAGE_LOADING;
            memzero(model->seed, 64);
            if(!model->mnemonic_only) {
                memzero((void*)model->mnemonic, strlen(model->mnemonic));
                free((void*)model->mnemonic);

                if(model->ask_hex) {
                    memzero((void*)model->ask_hex, 65);
                    free((void*)model->ask_hex);
                }
                if(model->nk_hex) {
                    memzero((void*)model->nk_hex, 65);
                    free((void*)model->nk_hex);
                }
                if(model->rivk_hex) {
                    memzero((void*)model->rivk_hex, 65);
                    free((void*)model->rivk_hex);
                }

                if(model->recv_address) {
                    memzero(model->recv_address, MAX_ADDR_BUF);
                    free(model->recv_address);
                }
                if(model->fvk_hex) {
                    memzero(model->fvk_hex, strlen(model->fvk_hex));
                    free(model->fvk_hex);
                    model->fvk_hex = NULL;
                }
                s_sign_page = 0;
            }
        },
        true);

    flipz_scene_1_clear_text();
}

void flipz_scene_1_enter(void* context) {
    furi_assert(context);
    FlipZScene1* instance = (FlipZScene1*)context;

    FlipZ* app = instance->context;

    int strength = 256;
    if(app->bip39_strength == FlipZStrength128) {
        strength = 128;
    } else if(app->bip39_strength == FlipZStrength192) {
        strength = 192;
    }

    const char* passphrase_text = "";
    if(app->passphrase == FlipZPassphraseOn && strlen(app->passphrase_text) > 0) {
        passphrase_text = app->passphrase_text;
    }

    const uint32_t coin_type = app->coin_type;
    const int view_mode = app->view_mode;
    bool overwrite = app->overwrite_saved_seed != 0;

    // FVK export
    if(view_mode == FlipZViewModeExportFVK) {
        CONFIDENTIAL uint8_t ask[32], ak[32], nk[32], rivk[32];
        bool keys_ok =
            wallet_load_keys(coin_type == CoinTypeZECOrchardTest, ask, ak, nk, rivk);

        if(!keys_ok) {
            char* mnemonic = malloc(TEXT_BUFFER_SIZE);
            if(!mnemonic || !wallet_load_mnemonic(mnemonic)) {
                if(mnemonic) free(mnemonic);
                with_view_model(
                    instance->view,
                    FlipZScene1Model * model,
                    {
                        model->mnemonic_only = true;
                        model->page = PAGE_MNEMONIC;
                        model->mnemonic = "ERROR:,Load error";
                    },
                    true);
                return;
            }
            uint8_t seed[64];
            mnemonic_to_seed(mnemonic, passphrase_text, seed, 0);
            memzero(mnemonic, TEXT_BUFFER_SIZE);
            free(mnemonic);

            CONFIDENTIAL uint8_t sk[32];
            uint32_t derive_coin = (coin_type == CoinTypeZECOrchardTest) ? 1 : 133;
            orchard_derive_account_sk(seed, derive_coin, DERIV_ACCOUNT, sk);
            orchard_derive_keys(sk, ask, nk, rivk);
            memzero(seed, 64);
            memzero(sk, 32);

            redpallas_derive_ak(ask, ak);
            wallet_save_keys(coin_type == CoinTypeZECOrchardTest, ask, ak, nk, rivk);
        }
        memzero(ask, 32);

        char* fvk = malloc(3 * 64 + 20);
        if(fvk) {
            char* p = fvk;
            p += sprintf(p, "ak:");
            flipz_btox(ak, 32, p);
            p += 64;
            p += sprintf(p, "\nnk:");
            flipz_btox(nk, 32, p);
            p += 64;
            p += sprintf(p, "\nrivk:");
            flipz_btox(rivk, 32, p);
        }
        if(fvk) {
            flipz_file_write("fvk.hex", fvk);
        }

        memzero(ak, 32);
        memzero(nk, 32);
        memzero(rivk, 32);

        with_view_model(
            instance->view,
            FlipZScene1Model * model,
            {
                model->fvk_hex = fvk;
                model->coin_type = coin_type;
                model->mnemonic_only = true;
                model->page = PAGE_FVK;
            },
            true);
        return;
    }

    // Sign mode
    if(view_mode == FlipZViewModeSign) {
        s_coin_label = (coin_type == CoinTypeZECOrchardTest) ? "TAZ" : "ZEC";
        uint32_t derive_coin = (coin_type == CoinTypeZECOrchardTest) ? 1 : 133;
        CONFIDENTIAL uint8_t ask[32], ak_key[32], nk_key[32], rivk_key[32];
        CONFIDENTIAL uint8_t t_sk[32];
        uint8_t t_pubkey[33];
        memzero(t_sk, 32);
        memzero(t_pubkey, 33);

        s_sign_page = PAGE_SIGN_INIT;
        with_view_model(
            instance->view,
            FlipZScene1Model * model,
            {
                model->mnemonic_only = true;
                model->page = PAGE_SERIAL;
            },
            true);

        // Seed is required for transparent (BIP-32) derivation.
        // Even when orchard keys are cached, we must load the mnemonic.
        char* mnemonic = malloc(TEXT_BUFFER_SIZE);
        if(!mnemonic) {
            s_sign_page = 0;
            with_view_model(
                instance->view,
                FlipZScene1Model * model,
                {
                    model->mnemonic_only = true;
                    model->page = PAGE_MNEMONIC;
                    model->mnemonic = "ERROR:,Out of memory";
                },
                true);
            return;
        }
        if(!wallet_load_mnemonic(mnemonic)) {
            free(mnemonic);
            s_sign_page = 0;
            with_view_model(
                instance->view,
                FlipZScene1Model * model,
                {
                    model->mnemonic_only = true;
                    model->page = PAGE_MNEMONIC;
                    model->mnemonic = "ERROR:,Load error";
                },
                true);
            return;
        }
        CONFIDENTIAL uint8_t seed[64];
        mnemonic_to_seed(mnemonic, passphrase_text, seed, 0);
        memzero(mnemonic, TEXT_BUFFER_SIZE);
        free(mnemonic);

        // Derive transparent spending key (BIP-32: m/44'/coin'/0'/0/0)
        if(bip32_derive_transparent_sk(seed, derive_coin, t_sk, t_pubkey) != 0) {
            memzero(t_sk, 32);
            memzero(t_pubkey, 33);
        }

        bool keys_ok = wallet_load_keys(
            coin_type == CoinTypeZECOrchardTest, ask, ak_key, nk_key, rivk_key);
        if(!keys_ok) {
            CONFIDENTIAL uint8_t sk[32];
            orchard_derive_account_sk(seed, derive_coin, DERIV_ACCOUNT, sk);
            orchard_derive_keys(sk, ask, nk_key, rivk_key);
            memzero(sk, 32);
            redpallas_derive_ak(ask, ak_key);
            wallet_save_keys(
                coin_type == CoinTypeZECOrchardTest, ask, ak_key, nk_key, rivk_key);
        }
        memzero(seed, 64);

        s_sign_page = PAGE_SIGN_WAIT;
        s_sign_confirmed = false;
        s_sign_cancelled = false;
        s_sign_done = false;
        with_view_model(
            instance->view,
            FlipZScene1Model * model,
            {
                model->coin_type = coin_type;
                model->mnemonic_only = true;
                model->page = PAGE_SERIAL;
            },
            true);

        SignWorkerCtx* sctx = malloc(sizeof(SignWorkerCtx));
        if(sctx) {
            memcpy(sctx->ask, ask, 32);
            memcpy(sctx->ak, ak_key, 32);
            memcpy(sctx->nk, nk_key, 32);
            memcpy(sctx->rivk, rivk_key, 32);
            memcpy(sctx->t_sk, t_sk, 32);
            memcpy(sctx->t_pubkey, t_pubkey, 33);
            sctx->testnet = (coin_type == CoinTypeZECOrchardTest);
            sctx->view = instance->view;
            instance->worker_thread = furi_thread_alloc_ex(
                "ZcashSign", 8192, sign_worker_thread, sctx);
            furi_thread_start(instance->worker_thread);
        }
        memzero(ask, 32);
        memzero(nk_key, 32);
        memzero(rivk_key, 32);
        memzero(ak_key, 32);
        memzero(t_sk, 32);
        return;
    }

    // Try loading address from cache
    if(view_mode == FlipZViewModeGenerate || view_mode == FlipZViewModeAddress) {
        const char* cache_file = (coin_type == CoinTypeZECOrchardTest)
                                     ? RECEIVE_FILE_TESTNET
                                     : RECEIVE_FILE_MAINNET;
        if(flipz_file_exists(cache_file)) {
            char* addr = malloc(MAX_ADDR_BUF);
            if(addr) {
                memzero(addr, MAX_ADDR_BUF);
                flipz_file_read(cache_file, addr, MAX_ADDR_BUF);
                if(strlen(addr) > 0) {
                    with_view_model(
                        instance->view,
                        FlipZScene1Model * model,
                        {
                            model->recv_address = addr;
                            model->coin_type = coin_type;
                            model->mnemonic_only = true;
                            model->page = PAGE_ADDR_ZEC;
                        },
                        true);
                    return;
                }
                free(addr);
            }
        }
    }

    // Start generation worker thread
    s_progress_view = instance->view;
    with_view_model(
        instance->view,
        FlipZScene1Model * model,
        { model->page = PAGE_LOADING; },
        true);

    GenWorkerCtx* wctx = malloc(sizeof(GenWorkerCtx));
    if(wctx) {
        wctx->strength = strength;
        wctx->coin_type = coin_type;
        wctx->overwrite = overwrite;
        wctx->view_mode = view_mode;
        wctx->view = instance->view;
        strncpy(wctx->passphrase, passphrase_text, TEXT_BUFFER_SIZE - 1);
        wctx->passphrase[TEXT_BUFFER_SIZE - 1] = '\0';

        instance->worker_thread =
            furi_thread_alloc_ex("ZcashGen", 8192, gen_worker_thread, wctx);
        furi_thread_start(instance->worker_thread);
    }
}

FlipZScene1* flipz_scene_1_alloc() {
    FlipZScene1* instance = malloc(sizeof(FlipZScene1));
    instance->view = view_alloc();
    instance->worker_thread = NULL;
    view_allocate_model(instance->view, ViewModelTypeLocking, sizeof(FlipZScene1Model));
    view_set_context(instance->view, instance);
    view_set_draw_callback(instance->view, (ViewDrawCallback)flipz_scene_1_draw);
    view_set_input_callback(instance->view, flipz_scene_1_input);
    view_set_enter_callback(instance->view, flipz_scene_1_enter);
    view_set_exit_callback(instance->view, flipz_scene_1_exit);

    with_view_model(
        instance->view,
        FlipZScene1Model * model,
        { model->page = PAGE_LOADING; },
        true);

    return instance;
}

void flipz_scene_1_free(FlipZScene1* instance) {
    furi_assert(instance);

    if(instance->worker_thread) {
        furi_thread_join(instance->worker_thread);
        furi_thread_free(instance->worker_thread);
    }

    view_free(instance->view);
    free(instance);
}

View* flipz_scene_1_get_view(FlipZScene1* instance) {
    furi_assert(instance);
    return instance->view;
}
