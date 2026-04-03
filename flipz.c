#include "flipz.h"
#include "helpers/flipz_file.h"
// From: lib/zcash
#include <memzero.h>
#include <bip39.h>

#define MNEMONIC_MENU_DEFAULT "Import mnemonic seed"
#define MNEMONIC_MENU_SUCCESS "Import seed (success)"
#define MNEMONIC_MENU_FAILURE "Import seed (failed!)"

char g_word_header[40]; // "Word NN/NN (retry)"

bool flipz_custom_event_callback(void* context, uint32_t event) {
    furi_assert(context);
    FlipZ* app = context;
    return scene_manager_handle_custom_event(app->scene_manager, event);
}

void flipz_tick_event_callback(void* context) {
    furi_assert(context);
    FlipZ* app = context;
    scene_manager_handle_tick_event(app->scene_manager);
}

bool flipz_navigation_event_callback(void* context) {
    furi_assert(context);
    FlipZ* app = context;
    return scene_manager_handle_back_event(app->scene_manager);
}

static void text_input_callback(void* context) {
    furi_assert(context);
    FlipZ* app = context;
    bool handled = false;

    if(strlen(app->input_text) > 0) {
        if(app->input_state == FlipZTextInputPassphrase) {
            if(app->passphrase == FlipZPassphraseOn) {
                strcpy(app->passphrase_text, app->input_text);
            }
            memzero(app->input_text, TEXT_BUFFER_SIZE);
            app->input_state = FlipZTextInputDefault;
            handled = true;
            view_dispatcher_switch_to_view(app->view_dispatcher, FlipZViewIdSettings);
        } else if(app->input_state == FlipZTextInputMnemonic) {
            if(app->import_from_mnemonic == 1) {
                // Force lowercase
                char* word = app->input_text;
                for(size_t i = 0; word[i]; i++) {
                    if(word[i] >= 'A' && word[i] <= 'Z') word[i] += 'a' - 'A';
                }

                // Strip trailing spaces
                size_t wlen = strlen(word);
                while(wlen > 0 && word[wlen - 1] == ' ') word[--wlen] = '\0';

                if(wlen == 0) {
                    memzero(app->input_text, TEXT_BUFFER_SIZE);
                    view_dispatcher_switch_to_view(app->view_dispatcher, FlipZViewIdTextInput);
                    return;
                }

                // Try to resolve the word: exact match or unique prefix
                const char* final_word = NULL;
                if(mnemonic_find_word(word) >= 0) {
                    final_word = word;
                } else {
                    int match_count = 0;
                    const char* match = NULL;
                    for(int i = 0; i < BIP39_WORD_COUNT && match_count < 2; i++) {
                        if(strncmp(BIP39_WORDLIST_ENGLISH[i], word, wlen) == 0) {
                            match = BIP39_WORDLIST_ENGLISH[i];
                            match_count++;
                        }
                    }
                    if(match_count == 1) {
                        final_word = match;
                    }
                }
                if(!final_word) {
                    memzero(app->input_text, TEXT_BUFFER_SIZE);
                    snprintf(
                        g_word_header,
                        sizeof(g_word_header),
                        "Word %d/%d (retry)",
                        app->import_word_index + 1,
                        app->import_word_count);
                    text_input_set_header_text(app->text_input, g_word_header);
                    view_dispatcher_switch_to_view(app->view_dispatcher, FlipZViewIdTextInput);
                    return;
                }

                // Append word to accumulated mnemonic
                size_t cur_len = strlen(app->import_mnemonic_text);
                if(cur_len > 0) {
                    app->import_mnemonic_text[cur_len] = ' ';
                    cur_len++;
                }
                strcpy(app->import_mnemonic_text + cur_len, final_word);
                app->import_word_index++;

                memzero(app->input_text, TEXT_BUFFER_SIZE);

                if(app->import_word_index < app->import_word_count) {
                    snprintf(
                        g_word_header,
                        sizeof(g_word_header),
                        "Word %d/%d",
                        app->import_word_index + 1,
                        app->import_word_count);
                    text_input_set_header_text(app->text_input, g_word_header);
                    view_dispatcher_switch_to_view(app->view_dispatcher, FlipZViewIdTextInput);
                    return;
                }

                // All words entered - validate full mnemonic and save
                int status = FlipZStatusSuccess;
                if(mnemonic_check(app->import_mnemonic_text) == 0)
                    status = FlipZStatusMnemonicCheckError;
                else if(!wallet_save_mnemonic(app->import_mnemonic_text))
                    status = FlipZStatusSaveError;

                if(status == FlipZStatusSuccess) {
                    wallet_delete();
                    flipz_file_delete("ua_mainnet_address.txt");
                    flipz_file_delete("ua_testnet_address.txt");
                    app->mnemonic_menu_text = MNEMONIC_MENU_SUCCESS;

                    memzero(app->import_mnemonic_text, TEXT_BUFFER_SIZE);
                    memzero(app->input_text, TEXT_BUFFER_SIZE);
                    app->input_state = FlipZTextInputDefault;
                    app->import_from_mnemonic = 0;
                    app->view_mode = FlipZViewModeGenerate;
                    app->coin_type = flipz_coin_type(app);
                    app->overwrite_saved_seed = 0;
                    scene_manager_next_scene(app->scene_manager, FlipZSceneScene_1);
                    return;
                } else {
                    app->mnemonic_menu_text = MNEMONIC_MENU_FAILURE;
                }

                memzero(app->import_mnemonic_text, TEXT_BUFFER_SIZE);
            }
            memzero(app->input_text, TEXT_BUFFER_SIZE);
            app->input_state = FlipZTextInputDefault;
            app->import_from_mnemonic = 0;
            handled = true;
            scene_manager_previous_scene(app->scene_manager);
        }
    }

    if(!handled) {
        memzero(app->input_text, TEXT_BUFFER_SIZE);
        app->input_state = FlipZTextInputDefault;
        view_dispatcher_switch_to_view(app->view_dispatcher, FlipZViewIdMenu);
    }
}

static void flipz_scene_renew_dialog_callback(DialogExResult result, void* context) {
    FlipZ* app = context;
    if(result == DialogExResultRight) {
        app->wallet_create(app);
    } else {
        view_dispatcher_switch_to_view(app->view_dispatcher, FlipZViewIdMenu);
    }
}

static void flipz_wallet_create(void* context) {
    FlipZ* app = context;
    furi_assert(app);
    app->view_mode = FlipZViewModeGenerate;
    app->coin_type = flipz_coin_type(app);
    app->overwrite_saved_seed = 1;
    scene_manager_set_scene_state(app->scene_manager, FlipZSceneMenu, SubmenuIndexScene1New);
    scene_manager_next_scene(app->scene_manager, FlipZSceneScene_1);
}

FlipZ* flipz_app_alloc() {
    FlipZ* app = malloc(sizeof(FlipZ));
    app->gui = furi_record_open(RECORD_GUI);

    app->view_dispatcher = view_dispatcher_alloc();

    app->scene_manager = scene_manager_alloc(&flipz_scene_handlers, app);
    view_dispatcher_set_event_callback_context(app->view_dispatcher, app);
    view_dispatcher_set_navigation_event_callback(
        app->view_dispatcher, flipz_navigation_event_callback);
    view_dispatcher_set_tick_event_callback(
        app->view_dispatcher, flipz_tick_event_callback, 100);
    view_dispatcher_set_custom_event_callback(app->view_dispatcher, flipz_custom_event_callback);
    app->submenu = submenu_alloc();

    // Settings
    app->bip39_strength = FlipZStrength256; // 256 bits (24 words)
    app->passphrase = FlipZPassphraseOff;

    // Load persisted testnet setting from wallet.dat
    app->testnet = wallet_load_testnet() ? FlipZTestnetOn : FlipZTestnetOff;

    // Main menu
    app->coin_type = flipz_coin_type(app);
    app->overwrite_saved_seed = 0;
    app->import_from_mnemonic = 0;
    app->mnemonic_menu_text = MNEMONIC_MENU_DEFAULT;

    // Text input
    app->input_state = FlipZTextInputDefault;

    view_dispatcher_add_view(
        app->view_dispatcher, FlipZViewIdMenu, submenu_get_view(app->submenu));
    app->flipz_scene_1 = flipz_scene_1_alloc();
    view_dispatcher_add_view(
        app->view_dispatcher, FlipZViewIdScene1, flipz_scene_1_get_view(app->flipz_scene_1));
    app->variable_item_list = variable_item_list_alloc();
    view_dispatcher_add_view(
        app->view_dispatcher,
        FlipZViewIdSettings,
        variable_item_list_get_view(app->variable_item_list));

    app->text_input = text_input_alloc();
    text_input_set_result_callback(
        app->text_input,
        text_input_callback,
        (void*)app,
        app->input_text,
        TEXT_BUFFER_SIZE,
        true);
    view_dispatcher_add_view(
        app->view_dispatcher, FlipZViewIdTextInput, text_input_get_view(app->text_input));

    app->wallet_create = flipz_wallet_create;
    app->renew_dialog = dialog_ex_alloc();
    dialog_ex_set_result_callback(app->renew_dialog, flipz_scene_renew_dialog_callback);
    dialog_ex_set_context(app->renew_dialog, app);
    dialog_ex_set_left_button_text(app->renew_dialog, "No");
    dialog_ex_set_right_button_text(app->renew_dialog, "Yes");
    dialog_ex_set_header(
        app->renew_dialog,
        "Current wallet\nwill be deleted!\nProceed?",
        16,
        12,
        AlignLeft,
        AlignTop);
    view_dispatcher_add_view(
        app->view_dispatcher, FlipZViewRenewConfirm, dialog_ex_get_view(app->renew_dialog));

    return app;
}

void flipz_app_free(FlipZ* app) {
    furi_assert(app);

    scene_manager_free(app->scene_manager);

    text_input_free(app->text_input);

    view_dispatcher_remove_view(app->view_dispatcher, FlipZViewIdMenu);
    view_dispatcher_remove_view(app->view_dispatcher, FlipZViewIdScene1);
    view_dispatcher_remove_view(app->view_dispatcher, FlipZViewIdSettings);
    view_dispatcher_remove_view(app->view_dispatcher, FlipZViewIdTextInput);
    submenu_free(app->submenu);

    view_dispatcher_remove_view(app->view_dispatcher, FlipZViewRenewConfirm);
    dialog_ex_free(app->renew_dialog);

    view_dispatcher_free(app->view_dispatcher);
    furi_record_close(RECORD_GUI);

    app->gui = NULL;

    memzero(app, sizeof(FlipZ));
    free(app);
}

int32_t flipz_app(void* p) {
    UNUSED(p);
    FlipZ* app = flipz_app_alloc();

    view_dispatcher_attach_to_gui(app->view_dispatcher, app->gui, ViewDispatcherTypeFullscreen);

    scene_manager_next_scene(app->scene_manager, FlipZSceneMenu);

    furi_hal_power_suppress_charge_enter();

    view_dispatcher_run(app->view_dispatcher);

    furi_hal_power_suppress_charge_exit();
    flipz_app_free(app);

    return 0;
}
