#include "flipz.h"
#include "helpers/flipz_file.h"
#include "helpers/flipz_secure.h"
// From: lib/zcash
#include <memzero.h>
#include <bip39.h>
#include <aead.h>          /* aead_self_test for boot-time crypto sanity */
#include <furi.h>
#include <string.h>

#define MNEMONIC_MENU_DEFAULT "Import mnemonic seed"
#define MNEMONIC_MENU_SUCCESS "Import seed (success)"
#define MNEMONIC_MENU_FAILURE "Import seed (failed!)"

char g_word_header[40]; // "Word NN/NN (retry)"

bool flipz_get_mnemonic(FlipZ* app, char* out, size_t out_len) {
    /* (1) Sealed wallet path: cached after a successful PIN unlock. */
    if(app->is_unlocked && app->cached_mnemonic[0] != '\0') {
        /* Bounded length scan — strnlen is not in the Flipper firmware
         * exported API surface. */
        size_t n = 0;
        const size_t cap = sizeof(app->cached_mnemonic);
        while(n < cap && app->cached_mnemonic[n] != '\0') n++;
        if(n + 1 > out_len) return false;
        memcpy(out, app->cached_mnemonic, n);
        out[n] = '\0';
        return true;
    }
    /* (2) Legacy path for pre-PIN installs. The boot routing only reaches
     * a sensitive operation through this branch when the device has a
     * legacy wallet.dat AND no sealed file. */
    if(!flipz_secure_wallet_exists() && wallet_exists()) {
        return wallet_load_mnemonic(out);
    }
    return false;
}

/**
 * Internal: drop on-disk wallet state + the in-memory mnemonic cache, but
 * KEEP pin_buf intact. Used right before flipz_secure_provision so the
 * fresh seal can read the user's just-confirmed PIN. Wallet-storage
 * cleanup only — no UI side-effects.
 */
static void flipz_storage_reset(FlipZ* app) {
    flipz_secure_wipe();      /* /ext/apps_data/flipz/wallet.sealed + .lockout */
    wallet_delete();          /* legacy wallet.dat + .bak */
    flipz_file_delete("ua_mainnet_address.txt");
    flipz_file_delete("ua_testnet_address.txt");
    flipz_file_delete("fvk.hex");
    memzero(app->cached_mnemonic, sizeof(app->cached_mnemonic));
    app->is_unlocked = false;
}

void flipz_full_wipe(FlipZ* app) {
    flipz_storage_reset(app);
    /* User-triggered wipe also clears any in-flight PIN material so the
     * next entry path starts from a known-zero state. flipz_storage_reset
     * is called in contexts (e.g. provisioning) where pin_buf is still
     * live, so the PIN scrub belongs only on the user-wipe path. */
    memzero(app->pin_buf, sizeof(app->pin_buf));
    memzero(app->pin_confirm_buf, sizeof(app->pin_confirm_buf));
    app->mnemonic_menu_text = MNEMONIC_MENU_DEFAULT;
}

/* Visible to other translation units that perform a pre-provisioning
 * cleanup; declared in flipz.h. */
void flipz_storage_reset_public(FlipZ* app) { flipz_storage_reset(app); }

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

                // All words entered - validate, seal under PIN, cache.
                int status = FlipZStatusSuccess;
                if(mnemonic_check(app->import_mnemonic_text) == 0) {
                    status = FlipZStatusMnemonicCheckError;
                } else {
                    /* Pin scene already collected & confirmed app->pin_buf
                     * before routing here (FlipZPinPostImport). Drop any
                     * legacy state (but keep pin_buf), then seal + cache. */
                    flipz_storage_reset_public(app);
                    const char* pp = (app->passphrase == FlipZPassphraseOn &&
                                      app->passphrase_text[0])
                                         ? app->passphrase_text
                                         : "";
                    if(flipz_secure_provision(
                           app->import_mnemonic_text, app->pin_buf, pp) !=
                       FLIPZ_PIN_OK) {
                        status = FlipZStatusSaveError;
                    } else {
                        memzero(app->cached_mnemonic, sizeof(app->cached_mnemonic));
                        strncpy(app->cached_mnemonic,
                                app->import_mnemonic_text,
                                sizeof(app->cached_mnemonic) - 1);
                        app->is_unlocked = true;
                        memzero(app->pin_buf, FLIPZ_PIN_LEN);
                    }
                }

                if(status == FlipZStatusSuccess) {
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

static void flipz_scene_wipe_dialog_callback(DialogExResult result, void* context) {
    FlipZ* app = context;
    if(result == DialogExResultRight) {
        flipz_full_wipe(app);                 /* sealed + legacy + cache */
        scene_manager_set_scene_state(app->scene_manager, FlipZSceneMenu, 0);
        submenu_reset(app->submenu);
        flipz_scene_menu_on_enter(app);
    } else {
        view_dispatcher_switch_to_view(app->view_dispatcher, FlipZViewIdMenu);
    }
}

static void flipz_wallet_create(void* context) {
    FlipZ* app = context;
    furi_assert(app);
    /* "Regenerate wallet" path: route through Pin (provisioning) so the
     * fresh seed is sealed under a freshly-set PIN. Without this the
     * worker thread would call flipz_secure_provision with whatever
     * pin_buf happens to contain (zeros on a fresh app launch), producing
     * a sealed file the user could never unlock. */
    app->view_mode = FlipZViewModeGenerate;
    app->coin_type = flipz_coin_type(app);
    app->overwrite_saved_seed = 1;
    app->import_from_mnemonic = 0;
    app->pin_mode = FlipZPinModeProvisionNew;
    app->pin_post_action = FlipZPinPostGenerate;
    scene_manager_set_scene_state(app->scene_manager, FlipZSceneMenu, SubmenuIndexScene1New);
    scene_manager_next_scene(app->scene_manager, FlipZScenePin);
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

    /* 5-slot PIN entry, custom view (see views/flipz_pin_input.c for why
     * the SDK's NumberInput was unusable for this). The Pin scene wires
     * the submit/cancel callbacks each time it switches to this view. */
    app->pin_input = flipz_pin_input_alloc();
    view_dispatcher_add_view(
        app->view_dispatcher, FlipZViewIdPinInput,
        flipz_pin_input_get_view(app->pin_input));

    /* Real progress bar shown while the PIN-unlock worker grinds PBKDF2.
     * The lib calls our progress cb every 512 iterations of HMAC-SHA512,
     * giving us ~1 % granularity at the 50 000-iter setting. */
    app->progress_view = flipz_progress_alloc();
    view_dispatcher_add_view(
        app->view_dispatcher, FlipZViewIdLoading,
        flipz_progress_get_view(app->progress_view));

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

    app->wipe_dialog = dialog_ex_alloc();
    dialog_ex_set_result_callback(app->wipe_dialog, flipz_scene_wipe_dialog_callback);
    dialog_ex_set_context(app->wipe_dialog, app);
    dialog_ex_set_left_button_text(app->wipe_dialog, "No");
    dialog_ex_set_right_button_text(app->wipe_dialog, "Yes");
    dialog_ex_set_header(
        app->wipe_dialog,
        "Wipe wallet?\nSeed + keys will be\nERASED forever.",
        8,
        10,
        AlignLeft,
        AlignTop);
    view_dispatcher_add_view(
        app->view_dispatcher, FlipZViewWipeConfirm, dialog_ex_get_view(app->wipe_dialog));

    return app;
}

void flipz_app_free(FlipZ* app) {
    furi_assert(app);

    /* Drain any in-flight PIN unlock worker so we don't free state from
     * underneath it. join() is a no-op if the thread already returned. */
    if(app->pin_worker) {
        furi_thread_join(app->pin_worker);
        furi_thread_free(app->pin_worker);
        app->pin_worker = NULL;
    }

    scene_manager_free(app->scene_manager);

    text_input_free(app->text_input);

    view_dispatcher_remove_view(app->view_dispatcher, FlipZViewIdMenu);
    view_dispatcher_remove_view(app->view_dispatcher, FlipZViewIdScene1);
    view_dispatcher_remove_view(app->view_dispatcher, FlipZViewIdSettings);
    view_dispatcher_remove_view(app->view_dispatcher, FlipZViewIdTextInput);
    view_dispatcher_remove_view(app->view_dispatcher, FlipZViewIdPinInput);
    flipz_pin_input_free(app->pin_input);
    view_dispatcher_remove_view(app->view_dispatcher, FlipZViewIdLoading);
    flipz_progress_free(app->progress_view);
    submenu_free(app->submenu);

    view_dispatcher_remove_view(app->view_dispatcher, FlipZViewRenewConfirm);
    dialog_ex_free(app->renew_dialog);

    view_dispatcher_remove_view(app->view_dispatcher, FlipZViewWipeConfirm);
    dialog_ex_free(app->wipe_dialog);

    view_dispatcher_free(app->view_dispatcher);
    furi_record_close(RECORD_GUI);

    app->gui = NULL;

    /* Defensive: scrub all secret state before free. memzero(app, sizeof)
     * already covers cached_mnemonic / pin_buf / passphrase_text, but call
     * it out so future field additions don't silently leak through. */
    memzero(app->cached_mnemonic, sizeof(app->cached_mnemonic));
    memzero(app->pin_buf, sizeof(app->pin_buf));
    memzero(app->pin_confirm_buf, sizeof(app->pin_confirm_buf));
    memzero(app->passphrase_text, sizeof(app->passphrase_text));
    memzero(app->pin_worker_mnemonic, sizeof(app->pin_worker_mnemonic));
    memzero(app, sizeof(FlipZ));
    free(app);
}

int32_t flipz_app(void* p) {
    UNUSED(p);

    /* Crypto sanity check: AES-CTR+HMAC-SHA256 roundtrip + tag-tamper +
     * AAD-tamper on hard-coded vectors. If this fails the device cannot
     * safely seal/unseal anything (toolchain regression, miscompile, bad
     * memory) — refuse to launch rather than corrupt user state. */
    if(aead_self_test() != 1) {
        FURI_LOG_E("FlipZ", "AEAD self-test FAILED — refusing to start");
        return 1;
    }

    FlipZ* app = flipz_app_alloc();

    view_dispatcher_attach_to_gui(app->view_dispatcher, app->gui, ViewDispatcherTypeFullscreen);

    /* Boot routing:
     *   - sealed wallet present → Pin scene (unlock); on success it then
     *     pushes the Menu scene with cached_mnemonic populated.
     *   - legacy plaintext wallet present and no sealed file → straight to
     *     menu, mnemonic is loaded on demand from wallet.dat.
     *   - no wallet at all → menu (fresh-install entry).
     * The Menu scene is always pushed so Back from a deeper scene returns
     * here cleanly; for unlock we push Pin AFTER Menu so its on-success
     * navigation pops back to Menu instead of leaving the dispatcher empty. */
    scene_manager_next_scene(app->scene_manager, FlipZSceneMenu);
    if(flipz_secure_wallet_exists()) {
        app->pin_mode = FlipZPinModeUnlock;
        app->pin_post_action = FlipZPinPostMenu;
        scene_manager_next_scene(app->scene_manager, FlipZScenePin);
    }

    furi_hal_power_suppress_charge_enter();

    view_dispatcher_run(app->view_dispatcher);

    furi_hal_power_suppress_charge_exit();
    flipz_app_free(app);

    return 0;
}
