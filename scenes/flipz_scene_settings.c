#include "../flipz.h"
#include "../helpers/flipz_file.h"
#include <lib/toolbox/value_index.h>
#include <memzero.h>

#define TEXT_LABEL_ON  "ON"
#define TEXT_LABEL_OFF "OFF"

const char* const bip39_strength_text[3] = {
    "12",
    "18",
    "24",
};
const uint32_t bip39_strength_value[3] = {
    FlipZStrength128,
    FlipZStrength192,
    FlipZStrength256,
};

const char* const passphrase_text[2] = {
    TEXT_LABEL_OFF,
    TEXT_LABEL_ON,
};
const uint32_t passphrase_value[2] = {
    FlipZPassphraseOff,
    FlipZPassphraseOn,
};

const char* const testnet_text[2] = {
    "Mainnet (ZEC)",
    "Testnet (TAZ)",
};
const uint32_t testnet_value[2] = {
    FlipZTestnetOff,
    FlipZTestnetOn,
};

static void flipz_scene_settings_set_bip39_strength(VariableItem* item) {
    FlipZ* app = variable_item_get_context(item);
    uint8_t index = variable_item_get_current_value_index(item);
    variable_item_set_current_value_text(item, bip39_strength_text[index]);
    app->bip39_strength = bip39_strength_value[index];
}

static void flipz_scene_settings_set_testnet(VariableItem* item) {
    FlipZ* app = variable_item_get_context(item);
    uint8_t index = variable_item_get_current_value_index(item);
    variable_item_set_current_value_text(item, testnet_text[index]);
    app->testnet = testnet_value[index];
    wallet_save_testnet(app->testnet == FlipZTestnetOn);
}

static void flipz_scene_settings_set_passphrase(VariableItem* item) {
    FlipZ* app = variable_item_get_context(item);
    uint8_t index = variable_item_get_current_value_index(item);
    variable_item_set_current_value_text(item, passphrase_text[index]);
    app->passphrase = passphrase_value[index];

    if(app->passphrase == FlipZPassphraseOn) {
        app->input_state = FlipZTextInputPassphrase;
        text_input_set_header_text(app->text_input, "Enter BIP39 passphrase");
        view_dispatcher_switch_to_view(app->view_dispatcher, FlipZViewIdTextInput);
    } else {
        memzero(app->passphrase_text, TEXT_BUFFER_SIZE);
    }
}

void flipz_scene_settings_submenu_callback(void* context, uint32_t index) {
    FlipZ* app = context;
    view_dispatcher_send_custom_event(app->view_dispatcher, index);
}

void flipz_scene_settings_on_enter(void* context) {
    FlipZ* app = context;
    VariableItem* item;
    uint8_t value_index;

    // Network mode
    item = variable_item_list_add(
        app->variable_item_list, "Network:", 2, flipz_scene_settings_set_testnet, app);
    value_index = value_index_uint32(app->testnet, testnet_value, 2);
    variable_item_set_current_value_index(item, value_index);
    variable_item_set_current_value_text(item, testnet_text[value_index]);

    // BIP39 strength
    item = variable_item_list_add(
        app->variable_item_list,
        "BIP39 Words:",
        3,
        flipz_scene_settings_set_bip39_strength,
        app);
    value_index = value_index_uint32(app->bip39_strength, bip39_strength_value, 3);
    variable_item_set_current_value_index(item, value_index);
    variable_item_set_current_value_text(item, bip39_strength_text[value_index]);

    // Passphrase
    item = variable_item_list_add(
        app->variable_item_list,
        "BIP39 Passphrase:",
        2,
        flipz_scene_settings_set_passphrase,
        app);
    value_index = value_index_uint32(app->passphrase, passphrase_value, 2);
    variable_item_set_current_value_index(item, value_index);
    variable_item_set_current_value_text(item, passphrase_text[value_index]);

    view_dispatcher_switch_to_view(app->view_dispatcher, FlipZViewIdSettings);
}

bool flipz_scene_settings_on_event(void* context, SceneManagerEvent event) {
    FlipZ* app = context;
    UNUSED(app);
    bool consumed = false;
    if(event.type == SceneManagerEventTypeCustom) {
    }
    return consumed;
}

void flipz_scene_settings_on_exit(void* context) {
    FlipZ* app = context;
    variable_item_list_set_selected_item(app->variable_item_list, 0);
    variable_item_list_reset(app->variable_item_list);
}
