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
#include "flipz_coins.h"

#define FLIPZ_VERSION    "v0.3"
#define TEXT_BUFFER_SIZE 256

typedef enum {
    FlipZTestnetOff,
    FlipZTestnetOn,
} FlipZTestnetState;

typedef struct {
    Gui* gui;
    ViewDispatcher* view_dispatcher;
    Submenu* submenu;
    SceneManager* scene_manager;
    VariableItemList* variable_item_list;
    TextInput* text_input;
    DialogEx* renew_dialog;
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

    void (*wallet_create)(void* context);
} FlipZ;

extern char g_word_header[40];

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
    FlipZViewRenewConfirm,
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
    SubmenuIndexSettings,
    SubmenuIndexNOP,
} SubmenuIndex;
