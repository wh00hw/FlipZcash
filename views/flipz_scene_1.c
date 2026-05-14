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
#include <pbkdf2.h>
#include <blake2b.h>
#include <segwit_addr.h>
#include <redpallas.h>
#include <hwp.h>
#include <orchard_signer.h>
#include <zip244.h>
#include <bip32.h>
#include <secp256k1.h>
#include <hwp_dispatcher.h>
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
#define PAGE_SIGN_REVIEW_OUTPUT 13   /* per-output recipient+value review */

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
    int keys_page;    // 0=ask/ak, 1=nk, 2=rivk (used by PAGE_KEYS and PAGE_FVK)
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
static volatile bool s_net_err_ack = false;   /* input handler sets this on any
                                                 button press while the network
                                                 mismatch screen is visible. */

// Per-output review state (PAGE_SIGN_REVIEW_OUTPUT)
static char s_review_ua[200];          /* full Bech32m UA for the output */
static uint64_t s_review_value = 0;     /* zatoshis */
static uint16_t s_review_index = 0;     /* 0-based */
static uint16_t s_review_total = 0;
/* Sub-page: 0 = address only (full UA on screen, no overlap with hint);
 * 1 = value + Confirm/Cancel. The user flips between the two with the
 * Right (next) and Left (back) buttons so they can read the entire UA
 * without it being squeezed against the hint line. */
static volatile uint8_t s_review_subpage = 0;

/* Companion-link status surfaced to every signing-flow page so the user can
 * always tell what the device is doing relative to the host (zipher-cli):
 *  - phase (idle / connected / verifying / signing / ...)
 *  - per-action progress N/M
 * Driven by hwp_dispatcher via the phase_update callback; read from the
 * draw functions. All access is plain assignment of word-sized values
 * and reads-of-pointers, so no lock needed on Cortex-M. */
static volatile HwpPhase s_link_phase = HWP_PHASE_IDLE;
static volatile uint16_t s_link_act_idx = 0;   /* 1-based; 0 = N/A */
static volatile uint16_t s_link_act_total = 0;

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

/* Pallas/Sinsemilla yield trampoline. pallas_yield() invokes this every 5
 * EC ops; we yield to the scheduler so the system thread-watchdog and
 * other Furi threads (USB CDC, GUI) get to run. Without this the FAP
 * monopolises the CPU for ~10–30 s during cmx recomputation, the watchdog
 * kills the app, and the host sees a TransportError("Broken pipe"). */
static void flipz_pallas_yield_cb(void* ctx) {
    (void)ctx;
    furi_thread_yield();
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
    FlipZ* app;          /* needed for sealed-wallet provisioning + cache */
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
    if(w->overwrite ||
       (!flipz_secure_wallet_exists() && !wallet_exists())) {
        if(w->overwrite) {
            /* Drop prior storage + cache (sealed file, legacy wallet.dat,
             * UA cache). Keep pin_buf intact — we need it 4 lines later
             * for flipz_secure_provision. The user-triggered Wipe entry
             * uses flipz_full_wipe which also scrubs pin_buf. */
            flipz_storage_reset_public(w->app);
        }
        int strength = w->strength;
        if(strength != 128 && strength != 192) strength = 256;
        const char* mnemonic_gen = mnemonic_generate(strength);
        if(!mnemonic_gen) {
            free(mnemonic);
            goto fail_save;
        }
        /* Seal under PIN-derived AEAD (audit H-5). Provisioning resets
         * the lockout counter and writes the sealed file atomically.
         * Wire pbkdf2's progress hook to the same scene_1 progress label
         * we already use for Sinsemilla, so the user sees the bar advance
         * during the ~1 s PBKDF2 instead of holding "Loading wallet...". */
        s_progress_pct = 0;
        s_progress_label = "Sealing wallet (PIN)...";
        s_progress_offset = 0;
        s_progress_scale = 5;    /* Subsequent step (Deriving seed) jumps
                                  * the bar to 5 %; reserve only the first
                                  * 5 % so the bar never regresses. */
        if(s_progress_view) {
            with_view_model(s_progress_view, FlipZScene1Model * model,
                            { UNUSED(model); }, true);
        }
        pbkdf2_set_progress_cb(flipz_progress_cb, NULL);
        FlipzPinResult pr = flipz_secure_provision(
            mnemonic_gen, w->app->pin_buf, w->passphrase);
        pbkdf2_set_progress_cb(NULL, NULL);
        s_progress_offset = 0;
        s_progress_scale = 100;
        if(pr != FLIPZ_PIN_OK) {
            mnemonic_clear();
            free(mnemonic);
            goto fail_save;
        }
        strncpy(mnemonic, mnemonic_gen, TEXT_BUFFER_SIZE - 1);
        mnemonic_clear();
        /* Mirror into the in-memory cache so the rest of this session can
         * derive keys/addresses without going through the SD card again. */
        memzero(w->app->cached_mnemonic, sizeof(w->app->cached_mnemonic));
        strncpy(w->app->cached_mnemonic, mnemonic, TEXT_BUFFER_SIZE - 1);
        w->app->is_unlocked = true;
        memzero(w->app->pin_buf, FLIPZ_PIN_LEN);
        just_generated = true;
    }

    if(!just_generated && !flipz_get_mnemonic(w->app, mnemonic, TEXT_BUFFER_SIZE)) {
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

// Sign worker context. Keys are NOT pre-derived on the GUI thread anymore —
// the worker pulls the mnemonic from the unlocked cache, derives BIP-32
// transparent + Orchard keys at startup with progress feedback, then enters
// the serial loop. Pre-derivation on the GUI thread caused 1–10 s of UI
// freeze depending on whether the keys cache hit.
typedef struct {
    char passphrase[TEXT_BUFFER_SIZE];
    uint32_t coin_type;   // 1 testnet, 133 mainnet (BIP-44 / ZIP-32 path)
    bool testnet;
    View* view;
    FlipZ* app;
} SignWorkerCtx;

/* ── HwpDispatcher callback adapters ──────────────────────────────────
 * The protocol-driving loop (drain → parse → dispatch → reply, plus
 * keepalive and IDLE detection) lives in libzcash-orchard-c's
 * hwp_dispatcher.c. The functions below adapt Flipper-specific
 * primitives (USB CDC, scene model updates, button wait loops) to the
 * dispatcher's HwpDispatcher{Io,Ui} callback shape. */

static size_t flipz_disp_drain(uint8_t* out, size_t out_cap, void* ctx) {
    UNUSED(ctx);
    return flipz_serial_drain_buf(out, out_cap);
}

static void flipz_disp_send(const uint8_t* data, size_t len, void* ctx) {
    UNUSED(ctx);
    flipz_serial_send_raw(data, len);
}

static uint32_t flipz_disp_tick(void* ctx) {
    UNUSED(ctx);
    return furi_get_tick();
}

static void flipz_disp_sleep(uint32_t ms, void* ctx) {
    UNUSED(ctx);
    /* Cooperative sleep: wake on RX-event flag (set by the CDC rx
     * callback in flipz_serial.c) or after the timeout, whichever
     * comes first. Equivalent to the original worker loop's
     * furi_thread_flags_wait. */
    furi_thread_flags_wait(1, FuriFlagWaitAny, ms);
}

static bool flipz_disp_should_exit(void* ctx) {
    UNUSED(ctx);
    return s_sign_page == 0;
}

static HwpUiResult flipz_disp_review_output(
    uint16_t idx_1_based, uint16_t total,
    const char* addr_str, uint64_t value, void* ctx) {
    SignWorkerCtx* w = (SignWorkerCtx*)ctx;
    /* The dispatcher pre-encodes the destination (Orchard UA or
     * transparent t-address) — copy into the display buffer the
     * renderer reads. Truncate defensively; the buffer is sized for
     * the longest UA the on-device library can produce. */
    {
        size_t cap = sizeof(s_review_ua) - 1;
        size_t i = 0;
        while(i < cap && addr_str[i] != '\0') {
            s_review_ua[i] = addr_str[i];
            i++;
        }
        s_review_ua[i] = '\0';
    }
    s_review_value = value;
    s_review_index = (uint16_t)(idx_1_based - 1);
    s_review_total = total;
    s_review_subpage = 0;  /* start on the address page, user pages to value */
    s_sign_confirmed = false;
    s_sign_cancelled = false;
    s_sign_page = PAGE_SIGN_REVIEW_OUTPUT;
    with_view_model(w->view, FlipZScene1Model * model, { UNUSED(model); }, true);

    while(!s_sign_confirmed && !s_sign_cancelled && s_sign_page != 0) {
        furi_delay_ms(100);
    }
    memzero(s_review_ua, sizeof(s_review_ua));
    s_review_value = 0;

    if(s_sign_page == 0) return HWP_UI_EXIT;
    return s_sign_confirmed ? HWP_UI_OK : HWP_UI_CANCELLED;
}

static HwpUiResult flipz_disp_confirm_tx(
    uint64_t amount, uint64_t fee, const char* recipient_str, void* ctx) {
    SignWorkerCtx* w = (SignWorkerCtx*)ctx;
    s_sign_amount = amount;
    s_sign_fee = fee;
    strncpy(s_sign_recipient, recipient_str, sizeof(s_sign_recipient) - 1);
    s_sign_recipient[sizeof(s_sign_recipient) - 1] = '\0';
    s_sign_confirmed = false;
    s_sign_cancelled = false;
    s_sign_done = false;
    s_sign_page = PAGE_SIGN_ADDR;
    with_view_model(w->view, FlipZScene1Model * model, { UNUSED(model); }, true);

    while(!s_sign_confirmed && !s_sign_cancelled && s_sign_page != 0) {
        furi_delay_ms(100);
    }
    if(s_sign_page == 0) return HWP_UI_EXIT;
    if(!s_sign_confirmed) {
        s_sign_page = PAGE_SIGN_WAIT;
        with_view_model(w->view, FlipZScene1Model * model, { UNUSED(model); }, true);
        return HWP_UI_CANCELLED;
    }
    return HWP_UI_OK;
}

static void flipz_disp_network_error(const char* msg, bool device_testnet,
                                      void* ctx) {
    SignWorkerCtx* w = (SignWorkerCtx*)ctx;
    UNUSED(device_testnet);
    s_net_err_msg = msg ? msg : "Network mismatch";
    s_sign_page = PAGE_SIGN_NET_ERR;
    s_net_err_ack = false;
    with_view_model(w->view, FlipZScene1Model * model, { UNUSED(model); }, true);
    /* Dismiss on any keypress, 5-second hard cap so a head-less device
     * still recovers automatically. */
    for(int i = 0; i < 50 && s_sign_page != 0 && !s_net_err_ack; i++) {
        furi_delay_ms(100);
    }
    if(s_sign_page == 0) return;
    s_sign_page = PAGE_SIGN_WAIT;
    with_view_model(w->view, FlipZScene1Model * model, { UNUSED(model); }, true);
}

static void flipz_disp_phase(HwpPhase phase_, uint16_t idx, uint16_t total,
                              void* ctx) {
    SignWorkerCtx* w = (SignWorkerCtx*)ctx;
    s_link_phase = phase_;
    s_link_act_idx = idx;
    s_link_act_total = total;
    /* During heavy crypto (cmx recomputation, RedPallas signing) the
     * standard PAGE_LOADING renderer with progress bar is what we want;
     * everything else falls back to the PAGE_SERIAL renderer which uses
     * s_sign_page to pick the appropriate per-state screen. */
    bool busy = (phase_ == HWP_PHASE_VERIFY || phase_ == HWP_PHASE_SIGNING);
    int desired_model_page = busy ? PAGE_LOADING : PAGE_SERIAL;

    /* Map dispatcher phase → s_sign_page so the PAGE_SERIAL fall-through
     * picks a coherent screen at every step:
     *   SIGNING        → PAGE_SIGN_DONE (s_sign_done=false → "Signing...")
     *   DONE           → PAGE_SIGN_DONE (s_sign_done=true  → "Signature sent!")
     *   IDLE / CONN    → PAGE_SIGN_WAIT (ready-for-next-tx home screen)
     * Phases that drive their own UI (REVIEW, AWAIT_CONFIRM via the
     * review_action/confirm_tx callbacks) set s_sign_page themselves. */
    int desired_sign_page = (int)s_sign_page;
    switch(phase_) {
    case HWP_PHASE_SIGNING:
        desired_sign_page = PAGE_SIGN_DONE;
        s_sign_done = false;
        break;
    case HWP_PHASE_DONE:
        desired_sign_page = PAGE_SIGN_DONE;
        s_sign_done = true;
        break;
    case HWP_PHASE_IDLE:
    case HWP_PHASE_CONNECTED:
        desired_sign_page = PAGE_SIGN_WAIT;
        break;
    default:
        break;
    }
    s_sign_page = desired_sign_page;

    with_view_model(
        w->view, FlipZScene1Model * model,
        { if(model->page != desired_model_page) model->page = desired_model_page; },
        true);
}

static void flipz_disp_progress(uint8_t pct, const char* label, void* ctx) {
    UNUSED(ctx);
    s_progress_pct = pct;
    s_progress_label = label;
}

// Worker thread: HWP v2 binary protocol for signing
static int32_t sign_worker_thread(void* ctx) {
    SignWorkerCtx* w = (SignWorkerCtx*)ctx;

    /* ===== Init phase: derive keys with progress feedback ============== */
    /* Per-thread crypto state; scrubbed in the cleanup block at the end.
     * Pre-derivation used to live on the GUI thread which froze the UI
     * for ~1 s (mnemonic_to_seed) and 5–10 s (Sinsemilla derive_keys on
     * cache miss). Doing it here lets the user see a real progress bar. */
    CONFIDENTIAL uint8_t ask[32], ak[32], nk[32], rivk[32];
    CONFIDENTIAL uint8_t t_sk[32];
    uint8_t t_pubkey[33];
    memzero(ask, 32); memzero(ak, 32); memzero(nk, 32); memzero(rivk, 32);
    memzero(t_sk, 32); memzero(t_pubkey, 33);

    pallas_set_progress_cb(flipz_progress_cb, NULL);
    pbkdf2_set_progress_cb(flipz_progress_cb, NULL);
    /* Wire a yield callback so multi-second Pallas/Sinsemilla loops do not
     * starve the Flipper scheduler — without this, the FAP thread never
     * relinquishes the CPU during cmx recomputation and the system thread-
     * watchdog kills the app (manifests host-side as a USB CDC "Broken
     * pipe"). pallas_yield() throttles to once-every-5-calls internally, so
     * the cost is minimal. */
    pallas_set_yield_cb(flipz_pallas_yield_cb, NULL);
    sinsemilla_lookup_init();
    s_progress_view = w->view;

    /* Switch the UI to the loading screen for the duration of init. The
     * sign-page renderer falls through to model->page when set, so this
     * shows the standard progress bar from PAGE_LOADING. */
    s_sign_page = PAGE_SIGN_INIT;
    s_progress_offset = 0;
    s_progress_scale = 5;
    s_progress_pct = 0;
    s_progress_label = "Loading mnemonic...";
    with_view_model(
        w->view,
        FlipZScene1Model * model,
        { model->page = PAGE_LOADING; },
        true);

    char mnemonic_buf[TEXT_BUFFER_SIZE];
    memzero(mnemonic_buf, sizeof(mnemonic_buf));
    if(!flipz_get_mnemonic(w->app, mnemonic_buf, sizeof(mnemonic_buf))) {
        memzero(mnemonic_buf, sizeof(mnemonic_buf));
        with_view_model(
            w->view,
            FlipZScene1Model * model,
            {
                model->mnemonic_only = true;
                model->page = PAGE_MNEMONIC;
                model->mnemonic = "ERROR:,No mnemonic available";
            },
            true);
        goto sign_done;
    }

    s_progress_offset = 5;
    s_progress_scale = 10;
    s_progress_label = "Deriving seed...";
    CONFIDENTIAL uint8_t seed[64];
    mnemonic_to_seed(mnemonic_buf, w->passphrase, seed, 0);
    memzero(mnemonic_buf, sizeof(mnemonic_buf));

    s_progress_offset = 15;
    s_progress_scale = 5;
    s_progress_pct = 15;
    s_progress_label = "BIP-32 transparent...";
    if(bip32_derive_transparent_sk(seed, w->coin_type, t_sk, t_pubkey) != 0) {
        memzero(t_sk, 32);
        memzero(t_pubkey, 33);
    }

    s_progress_offset = 20;
    s_progress_scale = 5;
    s_progress_label = "Loading Orchard keys...";
    bool keys_ok = wallet_load_keys(w->testnet, ask, ak, nk, rivk);
    if(!keys_ok) {
        /* Cache miss: derive Orchard ask/nk/rivk via Sinsemilla. The
         * pallas progress cb dominates here, mapping its 0..100 onto
         * the 25..100 % band. */
        s_progress_offset = 25;
        s_progress_scale = 75;
        s_progress_label = "Deriving Orchard keys...";
        CONFIDENTIAL uint8_t sk[32];
        orchard_derive_account_sk(seed, w->coin_type, DERIV_ACCOUNT, sk);
        orchard_derive_keys(sk, ask, nk, rivk);
        memzero(sk, 32);
        redpallas_derive_ak(ask, ak);
        wallet_save_keys(w->testnet, ask, ak, nk, rivk);
    }
    memzero(seed, 64);
    pbkdf2_set_progress_cb(NULL, NULL);

    /* Init done — flip the UI back to "Serial listening...". */
    s_progress_offset = 0;
    s_progress_scale = 100;
    s_sign_page = PAGE_SIGN_WAIT;
    with_view_model(
        w->view,
        FlipZScene1Model * model,
        { model->page = PAGE_SERIAL; },
        true);

    /* ===== Dispatcher invocation ====================================== */
    flipz_serial_init();

    OrchardSignerCtx signer_ctx;
    orchard_signer_init(&signer_ctx);

    /* Wire the FlipZ-specific I/O + UI primitives into the generic
     * hwp_dispatcher (libzcash-orchard-c). All target-agnostic protocol
     * logic — drain → parse → switch → reply, PING/PONG keepalive, IDLE
     * detection, multi-frame drain handling, recipient validation — now
     * lives in the library so every device target (FlipZcash, future
     * ESP32 / BOLOS) gets the same battle-tested driver instead of each
     * re-implementing it. */
    HwpDispatcher d = {
        .io = {
            .serial_drain  = flipz_disp_drain,
            .serial_send   = flipz_disp_send,
            .get_tick_ms   = flipz_disp_tick,
            .sleep_ms      = flipz_disp_sleep,
            .should_exit   = flipz_disp_should_exit,
        },
        .ui = {
            .review_output = flipz_disp_review_output,
            .confirm_tx    = flipz_disp_confirm_tx,
            .network_error = flipz_disp_network_error,
            .phase_update  = flipz_disp_phase,
            .progress      = flipz_disp_progress,
        },
        .keys = {
            .ak       = ak,
            .nk       = nk,
            .rivk     = rivk,
            .ask      = ask,
            .t_sk     = t_sk,
            .t_pubkey = t_pubkey,
        },
        .signer    = &signer_ctx,
        .testnet   = w->testnet,
        .user_ctx  = w,
    };

    hwp_dispatcher_run(&d);

    flipz_serial_deinit();

sign_done:
    /* Reached either via the normal serial-loop exit (s_sign_page == 0)
     * or via the early-error labels above. Scrub all key material on
     * stack before returning, deregister progress callbacks, drop the
     * Sinsemilla LUT handle. */
    pallas_set_progress_cb(NULL, NULL);
    pbkdf2_set_progress_cb(NULL, NULL);
    sinsemilla_lookup_deinit();
    memzero(ask, 32); memzero(ak, 32); memzero(nk, 32); memzero(rivk, 32);
    memzero(t_sk, 32); memzero(t_pubkey, 33);
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

/* Persistent footer (y=54..63) for every signing-flow page: shows the
 * companion-link status and per-action progress. A single static string
 * table keeps rodata small (each label costs only sizeof(ptr) in .data).
 * Caller is the GUI draw thread — read-only of volatile statics, no lock. */
static const char* const LINK_LABELS[] = {
    "idle", "conn", "meta", "verify", "review",
    "tparent", "ok?", "sign", "done", "err"
};
static void draw_link_footer(Canvas* canvas) {
    HwpPhase ph = s_link_phase;
    const char* lbl =
        ((unsigned)ph < sizeof(LINK_LABELS)/sizeof(LINK_LABELS[0]))
            ? LINK_LABELS[ph] : "?";
    char buf[24];
    if(s_link_act_total > 0 && s_link_act_idx > 0) {
        snprintf(buf, sizeof(buf), "%s  %u/%u",
                 lbl, (unsigned)s_link_act_idx, (unsigned)s_link_act_total);
    } else {
        snprintf(buf, sizeof(buf), "%s", lbl);
    }
    canvas_draw_line(canvas, 0, 54, 127, 54);
    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str_aligned(canvas, 64, 56, AlignCenter, AlignTop, buf);
}

void flipz_scene_1_draw(Canvas* canvas, FlipZScene1Model* model) {
    canvas_clear(canvas);
    canvas_set_color(canvas, ColorBlack);
    flipz_scene_1_clear_text();

    if(model->page == PAGE_LOADING) {
        canvas_set_font(canvas, FontPrimary);
        /* Title reflects what the heavy crypto underneath is actually
         * doing — "Generate address" during the receive-address flow,
         * "Signing transaction" during a sign session (any non-zero
         * s_sign_page means we're inside FlipZSceneScene_1's sign
         * branch rather than gen-address). */
        canvas_draw_str(canvas, 2, 10,
            (s_sign_page != 0) ? "Signing transaction" : "Generate address");
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
        /* Paginated: 1 key per page (3 lines of 22 hex chars). The full 64-char
         * hex never fit on a 128-px screen; old layout silently truncated it. */
        const char* labels[3] = {
            "ask (SPEND KEY!)",
            "nk (nullifier)",
            "rivk (commit rand)"};
        const char* hexes[3] = {
            model->ask_hex ? model->ask_hex : "",
            model->nk_hex ? model->nk_hex : "",
            model->rivk_hex ? model->rivk_hex : ""};
        int p = model->keys_page;
        if(p < 0 || p > 2) p = 0;

        canvas_set_font(canvas, FontPrimary);
        canvas_draw_str_aligned(canvas, 64, 2, AlignCenter, AlignTop, labels[p]);

        canvas_set_font(canvas, FontKeyboard);
        const char* hex = hexes[p];
        size_t hlen = strlen(hex);
        const int cpl = 22;
        char line[24];
        for(int row = 0; row < 3; row++) {
            size_t off = (size_t)(row * cpl);
            if(off >= hlen) break;
            size_t n = hlen - off;
            if(n > (size_t)cpl) n = (size_t)cpl;
            memcpy(line, hex + off, n);
            line[n] = '\0';
            canvas_draw_str_aligned(canvas, 64, 16 + row * 10, AlignCenter, AlignTop, line);
        }

        canvas_set_font(canvas, FontSecondary);
        char foot[20];
        snprintf(foot, sizeof(foot), "%d/3  [^v] navigate", p + 1);
        canvas_draw_str_aligned(canvas, 64, 58, AlignCenter, AlignCenter, foot);

    } else if(model->page == PAGE_MNEMONIC) {
        flipz_scene_1_draw_mnemonic(model->mnemonic);
        canvas_set_font(canvas, FontSecondary);
        for(int i = 0; i < DISP_LINE_COUNT; i++) {
            canvas_draw_str_aligned(
                canvas, 1, 2 + i * 10, AlignLeft, AlignTop, s_disp_lines[i]);
        }

    } else if(model->page == PAGE_FVK) {
        /* The FVK is stored as three concatenated 64-char hex strings:
         * fvk_hex[0..63]   = ak
         * fvk_hex[64..127] = nk
         * fvk_hex[128..191]= rivk
         * (no labels embedded — labels are drawn here so we can paginate). */
        const char* labels[3] = {"FVK: ak", "FVK: nk", "FVK: rivk"};
        int p = model->keys_page;
        if(p < 0 || p > 2) p = 0;

        canvas_set_font(canvas, FontPrimary);
        canvas_draw_str_aligned(canvas, 64, 2, AlignCenter, AlignTop, labels[p]);

        if(model->fvk_hex) {
            canvas_set_font(canvas, FontKeyboard);
            const char* hex = model->fvk_hex + (size_t)p * 64;
            const int cpl = 22;
            char line[24];
            for(int row = 0; row < 3; row++) {
                size_t off = (size_t)(row * cpl);
                if(off >= 64) break;
                size_t n = 64 - off;
                if(n > (size_t)cpl) n = (size_t)cpl;
                memcpy(line, hex + off, n);
                line[n] = '\0';
                canvas_draw_str_aligned(
                    canvas, 64, 16 + row * 10, AlignCenter, AlignTop, line);
            }
        }

        canvas_set_font(canvas, FontSecondary);
        char foot[20];
        snprintf(foot, sizeof(foot), "%d/3  [^v] navigate", p + 1);
        canvas_draw_str_aligned(canvas, 64, 58, AlignCenter, AlignCenter, foot);

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
            canvas, 64, 16, AlignCenter, AlignCenter, "Hardware Wallet");
        canvas_set_font(canvas, FontSecondary);
        canvas_draw_str_aligned(
            canvas, 64, 36, AlignCenter, AlignCenter, "Awaiting host...");
        draw_link_footer(canvas);

    } else if(s_sign_page == PAGE_SIGN_REVIEW_OUTPUT) {
        /* Per-output review: a single-screen view of one recipient.
         * Layout sized for 64-px display:
         *   y=1..10  header  "Output N/M" (FontPrimary)
         *   y=12..46 UA wrap (5 lines × 7 px FontKeyboard = 35 px,
         *            ≤ 110 chars; covers typical Orchard UAs without
         *            truncation, t-addrs fit in 1-2 lines)
         *   y=48..54 value   (FontSecondary)
         *   y=56..63 hint    "[OK] Confirm   [<] Cancel"
         *
         * One screen, one OK to confirm. The original two-sub-page
         * design was clearer in isolation but trapped the user in
         * navigation confusion across 3+ outputs × 2 sub-pages × 2-3
         * buttons; flattening to one screen halves the button budget.
         * Per-action confirmation remains a security invariant: the
         * library refuses to advance to VERIFIED unless every captured
         * action has been confirmed. */
        canvas_set_font(canvas, FontPrimary);
        char hdr[24];
        snprintf(hdr, sizeof(hdr), "Output %u/%u",
                 (unsigned)(s_review_index + 1), (unsigned)s_review_total);
        canvas_draw_str_aligned(canvas, 64, 1, AlignCenter, AlignTop, hdr);

        canvas_set_font(canvas, FontKeyboard);
        {
            const int chars_per_line = 22;
            const int y_start = 12;
            const int line_h = 7;
            const int max_lines = 5;
            size_t len = strlen(s_review_ua);
            for(int row = 0; row < max_lines && (size_t)(row * chars_per_line) < len; row++) {
                char line[24];
                size_t offset = row * chars_per_line;
                size_t n = len - offset;
                if(n > (size_t)chars_per_line) n = chars_per_line;
                if(row == max_lines - 1 && (offset + n) < len) {
                    if(n > 3) n -= 3;
                    memcpy(line, s_review_ua + offset, n);
                    memcpy(line + n, "...", 3);
                    line[n + 3] = '\0';
                } else {
                    memcpy(line, s_review_ua + offset, n);
                    line[n] = '\0';
                }
                canvas_draw_str_aligned(
                    canvas, 64, y_start + row * line_h, AlignCenter, AlignTop, line);
            }
        }
        canvas_set_font(canvas, FontSecondary);
        {
            char vbuf[32];
            snprintf(vbuf, sizeof(vbuf), "%lu.%08lu %s",
                     (unsigned long)(s_review_value / 100000000ULL),
                     (unsigned long)(s_review_value % 100000000ULL),
                     s_coin_label);
            canvas_draw_str_aligned(canvas, 64, 48, AlignCenter, AlignTop, vbuf);
        }
        canvas_draw_str_aligned(
            canvas, 64, 57, AlignCenter, AlignTop,
            "[OK] Confirm   [<] Cancel");

    } else if(s_sign_page == PAGE_SIGN_ADDR) {
        /* Final-confirmation step 1 of 2: full UA across the screen.
         * Right advances to PAGE_SIGN_AMOUNT (step 2) which shows the
         * amount + fee and asks for the final OK. */
        canvas_set_font(canvas, FontPrimary);
        canvas_draw_str_aligned(
            canvas, 64, 1, AlignCenter, AlignTop, "Recipient");
        canvas_set_font(canvas, FontKeyboard);
        const int chars_per_line = 22;
        const int y_start = 13;
        const int line_h = 7;
        const int max_lines = 6;
        size_t len = strlen(s_sign_recipient);
        for(int row = 0; row < max_lines && (size_t)(row * chars_per_line) < len; row++) {
            char line[24];
            size_t offset = row * chars_per_line;
            size_t n = len - offset;
            if(n > (size_t)chars_per_line) n = chars_per_line;
            if(row == max_lines - 1 && (offset + n) < len) {
                if(n > 3) n -= 3;
                memcpy(line, s_sign_recipient + offset, n);
                memcpy(line + n, "...", 3);
                line[n + 3] = '\0';
            } else {
                memcpy(line, s_sign_recipient + offset, n);
                line[n] = '\0';
            }
            canvas_draw_str_aligned(
                canvas, 64, y_start + row * line_h, AlignCenter, AlignTop, line);
        }
        canvas_set_font(canvas, FontSecondary);
        canvas_draw_str_aligned(
            canvas, 64, 57, AlignCenter, AlignTop,
            "[>] Next   [<] Cancel");

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
        canvas_draw_str_aligned(
            canvas, 64, 58, AlignCenter, AlignCenter, "[OK] Dismiss");

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
        draw_link_footer(canvas);
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
    /* PAGE_LOADING is shown during multi-second crypto (Sinsemilla cmx
     * recompute, ZIP-244 sighash, RedPallas sign, PBKDF2). We ignore most
     * keys so accidental presses don't fall through into half-rendered
     * pages, but Back must still escape — otherwise a stuck device leaves
     * the user with no way out short of pulling USB. The worker thread
     * polls `s_sign_page == 0` between operations, so flipping that flag
     * unblocks the per-output review and SIGN_REQ wait loops too. */
    if(busy) {
        if(event->type == InputTypeRelease && event->key == InputKeyBack) {
            s_sign_page = 0;
            s_sign_cancelled = true;
            instance->callback(FlipZCustomEventScene1Back, instance->context);
        }
        return true;
    }

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
                    } else if(s_sign_page == PAGE_SIGN_REVIEW_OUTPUT) {
                        s_sign_confirmed = true;
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
                    } else if(s_sign_page == PAGE_SIGN_ADDR) {
                        /* OK on the address page advances to the
                         * amount confirmation page — same as Right.
                         * Without this, OK does nothing here and the
                         * user is likely to press Back/Left in
                         * frustration, cancelling the whole flow. */
                        s_sign_page = PAGE_SIGN_AMOUNT;
                    } else if(s_sign_page == PAGE_SIGN_AMOUNT) {
                        s_sign_confirmed = true;
                    } else if(s_sign_page == PAGE_SIGN_REVIEW_OUTPUT) {
                        s_sign_confirmed = true;
                    } else if(s_sign_page == PAGE_SIGN_NET_ERR) {
                        s_net_err_ack = true;
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
                    } else if(s_sign_page == PAGE_SIGN_REVIEW_OUTPUT) {
                        s_sign_cancelled = true;
                    }
                },
                true);
            break;
        case InputKeyDown:
            with_view_model(
                instance->view,
                FlipZScene1Model * model,
                {
                    if(model->page == PAGE_KEYS || model->page == PAGE_FVK) {
                        model->keys_page = (model->keys_page + 1) % 3;
                    }
                },
                true);
            break;
        case InputKeyUp:
            with_view_model(
                instance->view,
                FlipZScene1Model * model,
                {
                    if(model->page == PAGE_KEYS || model->page == PAGE_FVK) {
                        model->keys_page = (model->keys_page + 2) % 3;
                    }
                },
                true);
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

            /* `mnemonic_only` historically meant "we own the mnemonic
             * pointer too" — but FVK / cached-UA paths set it true and
             * still allocate recv_address / fvk_hex. So free everything
             * we might own, NULL-check each pointer, and gate the
             * mnemonic free on the bit. */
            if(!model->mnemonic_only && model->mnemonic) {
                memzero((void*)model->mnemonic, strlen(model->mnemonic));
                free((void*)model->mnemonic);
            }
            model->mnemonic = NULL;

            if(model->ask_hex) {
                memzero((void*)model->ask_hex, 65);
                free((void*)model->ask_hex);
                model->ask_hex = NULL;
            }
            if(model->nk_hex) {
                memzero((void*)model->nk_hex, 65);
                free((void*)model->nk_hex);
                model->nk_hex = NULL;
            }
            if(model->rivk_hex) {
                memzero((void*)model->rivk_hex, 65);
                free((void*)model->rivk_hex);
                model->rivk_hex = NULL;
            }
            if(model->recv_address) {
                memzero(model->recv_address, MAX_ADDR_BUF);
                free(model->recv_address);
                model->recv_address = NULL;
            }
            if(model->fvk_hex) {
                memzero(model->fvk_hex, strlen(model->fvk_hex));
                free(model->fvk_hex);
                model->fvk_hex = NULL;
            }
            model->keys_page = 0;
            model->addr_subpage = 0;
            s_sign_page = 0;
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
            if(!mnemonic || !flipz_get_mnemonic(app, mnemonic, TEXT_BUFFER_SIZE)) {
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

        /* In-memory: 3*64 hex chars concatenated (ak||nk||rivk), used by the
         * paginated PAGE_FVK renderer. */
        char* fvk = malloc(3 * 64 + 1);
        if(fvk) {
            flipz_btox(ak, 32, fvk);
            flipz_btox(nk, 32, fvk + 64);
            flipz_btox(rivk, 32, fvk + 128);
            fvk[192] = '\0';

            /* On-disk: human-readable form with labels + newlines, kept
             * compatible with the existing exporter format that companion
             * tools / users expect. */
            char fvk_disk[3 * 64 + 20];
            char* dp = fvk_disk;
            dp += sprintf(dp, "ak:");
            memcpy(dp, fvk, 64);          dp += 64;
            dp += sprintf(dp, "\nnk:");
            memcpy(dp, fvk + 64, 64);     dp += 64;
            dp += sprintf(dp, "\nrivk:");
            memcpy(dp, fvk + 128, 64);    dp += 64;
            *dp = '\0';
            flipz_file_write("fvk.hex", fvk_disk);
            memzero(fvk_disk, sizeof(fvk_disk));
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

    // Sign mode — all derivation now happens inside the worker so the
    // GUI thread doesn't freeze on the first-sign Sinsemilla key derive.
    if(view_mode == FlipZViewModeSign) {
        s_coin_label = (coin_type == CoinTypeZECOrchardTest) ? "TAZ" : "ZEC";
        s_sign_confirmed = false;
        s_sign_cancelled = false;
        s_sign_done     = false;
        s_sign_page     = PAGE_SIGN_INIT;
        s_progress_view = instance->view;

        with_view_model(
            instance->view,
            FlipZScene1Model * model,
            {
                model->coin_type = coin_type;
                model->mnemonic_only = true;
                model->page = PAGE_LOADING;
            },
            true);

        SignWorkerCtx* sctx = malloc(sizeof(SignWorkerCtx));
        if(!sctx) {
            with_view_model(
                instance->view,
                FlipZScene1Model * model,
                {
                    model->mnemonic_only = true;
                    model->page = PAGE_MNEMONIC;
                    model->mnemonic = "ERROR:,Out of memory";
                },
                true);
            s_sign_page = 0;
            return;
        }
        memzero(sctx, sizeof(*sctx));
        sctx->coin_type = (coin_type == CoinTypeZECOrchardTest) ? 1u : 133u;
        sctx->testnet   = (coin_type == CoinTypeZECOrchardTest);
        sctx->view      = instance->view;
        sctx->app       = app;
        strncpy(sctx->passphrase, passphrase_text, TEXT_BUFFER_SIZE - 1);
        sctx->passphrase[TEXT_BUFFER_SIZE - 1] = '\0';

        instance->worker_thread = furi_thread_alloc_ex(
            "ZcashSign", 10240, sign_worker_thread, sctx);
        furi_thread_start(instance->worker_thread);
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
        wctx->app = app;
        strncpy(wctx->passphrase, passphrase_text, TEXT_BUFFER_SIZE - 1);
        wctx->passphrase[TEXT_BUFFER_SIZE - 1] = '\0';

        instance->worker_thread =
            /* 10 KB: enough for Sinsemilla (with the SD-backed LUT — the
             * deep-recursion fallback path is not on this thread) plus
             * the H-5 sealing primitives (PBKDF2-HMAC-SHA512 ctx ~360 B,
             * AEAD pt_buf 240 + file_buf 310 + key 64 + tag 32 ≈ 1 KB).
             * 16 KB was a debug over-allocation — the FAP heap on
             * STM32WB55 is ~50 KB shared with the rest of view state, so
             * a 16 KB thread stack starves the small mallocs that follow
             * (mnemonic[256], addr[129], hex_buf[65]×3) and the user
             * sees "Out of memory" from the worker's first malloc. */
            furi_thread_alloc_ex("ZcashGen", 10240, gen_worker_thread, wctx);
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
