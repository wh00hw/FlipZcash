#pragma once

#include <furi.h>
#include <furi_hal.h>
#include <gui/gui.h>
#include <input/input.h>
#include <stdlib.h>
#include <gui/view_dispatcher.h>
#include <gui/modules/submenu.h>
#include <gui/scene_manager.h>
#include <gui/modules/dialog_ex.h>
#include <gui/modules/variable_item_list.h>
#include <gui/modules/text_input.h>
#include "scenes/flipz_scene.h"
#include "views/flipz_scene_1.h"
#include "views/flipz_progress.h"
#include "views/flipz_pin_input.h"
#include "flipz_coins.h"
#include "helpers/flipz_secure.h"

#define FLIPZ_VERSION    "v0.3"
#define TEXT_BUFFER_SIZE 256

typedef enum {
    FlipZTestnetOff,
    FlipZTestnetOn,
} FlipZTestnetState;

typedef enum {
    FlipZPinModeUnlock = 0,           /* Boot/sensitive-op: enter PIN to unseal */
    FlipZPinModeProvisionNew,         /* Step 1 of new wallet: pick a PIN */
    FlipZPinModeProvisionConfirm,     /* Step 2: re-enter to confirm */
    FlipZPinModeChangeOld,            /* Settings: enter current PIN */
    FlipZPinModeChangeNew,            /* Settings: pick new PIN */
    FlipZPinModeChangeConfirm,        /* Settings: re-enter new PIN */
} FlipZPinMode;

/** What the pin scene should do once provisioning completes successfully. */
typedef enum {
    FlipZPinPostNone = 0,
    FlipZPinPostGenerate,             /* push scene_1 with overwrite=1, generate=1 */
    FlipZPinPostImport,               /* push scene_1 import flow */
    FlipZPinPostMenu,                 /* return to menu (used after change-pin) */
} FlipZPinPostAction;

typedef struct {
    Gui* gui;
    ViewDispatcher* view_dispatcher;
    Submenu* submenu;
    SceneManager* scene_manager;
    VariableItemList* variable_item_list;
    TextInput* text_input;
    FlipZPinInput* pin_input;          /* Custom 5-slot PIN view (replaces SDK NumberInput) */
    FlipZProgressView* progress_view;  /* PBKDF2 progress bar (Pin scene) */
    DialogEx* renew_dialog;
    DialogEx* wipe_dialog;
    FlipZScene1* flipz_scene_1;
    char* mnemonic_menu_text;
    // Settings options
    int bip39_strength;
    int passphrase;
    int testnet;
    // Main menu options
    int coin_type;
    int view_mode; // 0=address, 1=keys, 2=mnemonic
    int overwrite_saved_seed;
    int import_from_mnemonic;
    int import_word_index; // current word (0-based) during word-by-word import
    int import_word_count; // total words expected (12, 18, 24)
    // Text input
    int input_state;
    char passphrase_text[TEXT_BUFFER_SIZE];
    char import_mnemonic_text[TEXT_BUFFER_SIZE];
    char input_text[TEXT_BUFFER_SIZE];

    // PIN / sealed-wallet state
    int pin_mode;                            /* FlipZPinMode */
    int pin_post_action;                     /* FlipZPinPostAction */
    uint8_t pin_buf[FLIPZ_PIN_LEN];          /* current PIN being entered */
    uint8_t pin_confirm_buf[FLIPZ_PIN_LEN];  /* held during the two-step flow */
    bool is_unlocked;                        /* true once mnemonic is in cache */
    char cached_mnemonic[TEXT_BUFFER_SIZE];  /* live only while unlocked */

    /* PIN unlock worker: PBKDF2-HMAC-SHA512(50000) is ~1s on STM32WB55 and
     * was previously running on the dispatcher's GUI thread, which froze
     * the UI and risked blowing the FAP main-thread stack. The worker
     * does the heavy crypto on its own stack and posts
     * FlipZCustomEventPinUnlockDone when finished. */
    FuriThread* pin_worker;
    int pin_worker_result;                   /* FlipzPinResult from worker */
    char pin_worker_mnemonic[TEXT_BUFFER_SIZE]; /* unsealed plaintext from worker */

    void (*wallet_create)(void* context);
} FlipZ;

extern char g_word_header[40];

/**
 * Encode a 5-digit decimal PIN (0..99999) into the byte form the libzcash
 * AEAD KDF expects (one decimal digit per byte, MSD first). Identical
 * encoding is reproduced ESP32-side; do not change without updating the
 * companion target.
 */
static inline void flipz_pin_int_to_bytes(int32_t n, uint8_t out[FLIPZ_PIN_LEN]) {
    if(n < 0) n = 0;
    if(n > 99999) n = 99999;
    for(int i = FLIPZ_PIN_LEN - 1; i >= 0; i--) {
        out[i] = (uint8_t)(n % 10);
        n /= 10;
    }
}

static inline int32_t flipz_pin_bytes_to_int(const uint8_t pin[FLIPZ_PIN_LEN]) {
    int32_t n = 0;
    for(int i = 0; i < FLIPZ_PIN_LEN; i++) n = n * 10 + (pin[i] % 10);
    return n;
}

/**
 * Resolve the mnemonic for the active wallet. Order:
 *   1) sealed wallet unlocked this session → cached_mnemonic
 *   2) legacy unencrypted wallet.dat (RC4 obfuscation; pre-PIN installs)
 * Returns false if neither applies (caller treats as "no wallet").
 */
bool flipz_get_mnemonic(FlipZ* app, char* out, size_t out_len);

/** Wipe sealed + legacy storage and clear the in-memory cache.
 *  ALSO scrubs pin_buf — for user-driven "Wipe wallet" only. */
void flipz_full_wipe(FlipZ* app);

/** Pre-provisioning cleanup: drops storage + cache but PRESERVES pin_buf
 *  so flipz_secure_provision can use the just-collected PIN. */
void flipz_storage_reset_public(FlipZ* app);

// Helper: get coin type from testnet flag
static inline uint32_t flipz_coin_type(const FlipZ* app) {
    return (app->testnet == FlipZTestnetOn) ? CoinTypeZECOrchardTest : CoinTypeZECOrchard;
}

// Helper: currency label
static inline const char* flipz_coin_label(const FlipZ* app) {
    return (app->testnet == FlipZTestnetOn) ? "TAZ" : "ZEC";
}

typedef enum {
    FlipZViewIdStartscreen,
    FlipZViewIdMenu,
    FlipZViewIdScene1,
    FlipZViewIdSettings,
    FlipZViewIdTextInput,
    FlipZViewIdPinInput,
    FlipZViewIdLoading,
    FlipZViewRenewConfirm,
    FlipZViewWipeConfirm,
} FlipZViewId;

typedef enum {
    FlipZStrength128,
    FlipZStrength192,
    FlipZStrength256,
} FlipZStrengthState;

typedef enum {
    FlipZPassphraseOff,
    FlipZPassphraseOn,
} FlipZPassphraseState;

typedef enum {
    FlipZTextInputDefault,
    FlipZTextInputPassphrase,
    FlipZTextInputMnemonic
} FlipZTextInputState;

typedef enum {
    FlipZStatusSuccess = 0,
    FlipZStatusReturn = 10,
    FlipZStatusLoadError = 11,
    FlipZStatusSaveError = 12,
    FlipZStatusMnemonicCheckError = 13,
} FlipZStatus;

typedef enum {
    FlipZViewModeAddress = 0,
    FlipZViewModeGenerate = 1,
    FlipZViewModeKeys = 2,
    FlipZViewModeMnemonic = 3,
    FlipZViewModeExportFVK = 4,
    FlipZViewModeSign = 5,
} FlipZViewMode;

typedef enum {
    SubmenuIndexViewAddr = 0,
    SubmenuIndexGenAddr,
    SubmenuIndexKeys,
    SubmenuIndexMnemonic,
    SubmenuIndexScene1New,
    SubmenuIndexScene1Renew,
    SubmenuIndexScene1Import,
    SubmenuIndexExportFVK,
    SubmenuIndexSign,
    SubmenuIndexWipe,
    SubmenuIndexChangePin,
    SubmenuIndexSettings,
    SubmenuIndexNOP,
} SubmenuIndex;
