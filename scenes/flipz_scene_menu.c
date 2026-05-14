#include "../flipz.h"
#include "../helpers/flipz_file.h"
#include "../helpers/flipz_secure.h"
#include <string.h>

void flipz_scene_menu_submenu_callback(void* context, uint32_t index) {
    furi_assert(context);
    FlipZ* app = context;
    view_dispatcher_send_custom_event(app->view_dispatcher, index);
}

void flipz_scene_menu_on_enter(void* context) {
    FlipZ* app = context;

    /* on_enter fires both on initial push AND when the menu is revealed
     * from underneath a popped Pin/Settings/Scene_1. Reset the submenu so
     * the second entry doesn't double-render every item on top of the
     * stale ones from the first push. (Furi's scene manager calls
     * on_exit only when the menu itself is popped, not when something
     * lands on top of it, so on_exit's reset isn't enough.) */
    submenu_reset(app->submenu);

    /* "Has a wallet" = either the new sealed file or the legacy wallet.dat.
     * The Generate/Import branch only fires when neither exists. */
    bool has_wallet = flipz_secure_wallet_exists() || wallet_exists();

    const char* net_label = (app->testnet == FlipZTestnetOn) ? "TAZ" : "ZEC";

    if(has_wallet) {
        char addr_label[32];
        snprintf(addr_label, sizeof(addr_label), "%s Address", net_label);
        submenu_add_item(
            app->submenu,
            addr_label,
            SubmenuIndexGenAddr,
            flipz_scene_menu_submenu_callback,
            app);

        submenu_add_item(
            app->submenu,
            "USB Serial Signer",
            SubmenuIndexSign,
            flipz_scene_menu_submenu_callback,
            app);
        submenu_add_item(
            app->submenu,
            "Keys (Advanced)",
            SubmenuIndexKeys,
            flipz_scene_menu_submenu_callback,
            app);
        submenu_add_item(
            app->submenu,
            "Mnemonic",
            SubmenuIndexMnemonic,
            flipz_scene_menu_submenu_callback,
            app);
        submenu_add_item(
            app->submenu,
            "Export FVK",
            SubmenuIndexExportFVK,
            flipz_scene_menu_submenu_callback,
            app);
        submenu_add_item(
            app->submenu,
            "Regenerate wallet",
            SubmenuIndexScene1Renew,
            flipz_scene_menu_submenu_callback,
            app);
        /* Change PIN is only meaningful for sealed wallets. Legacy
         * wallet.dat is unencrypted; users on that path must wipe + create
         * a new wallet to gain a PIN. */
        if(flipz_secure_wallet_exists()) {
            submenu_add_item(
                app->submenu,
                "Change PIN",
                SubmenuIndexChangePin,
                flipz_scene_menu_submenu_callback,
                app);
        }
        submenu_add_item(
            app->submenu,
            "Wipe wallet",
            SubmenuIndexWipe,
            flipz_scene_menu_submenu_callback,
            app);
    } else {
        submenu_add_item(
            app->submenu,
            "Generate new wallet",
            SubmenuIndexScene1New,
            flipz_scene_menu_submenu_callback,
            app);
    }
    submenu_add_item(
        app->submenu,
        app->mnemonic_menu_text,
        SubmenuIndexScene1Import,
        flipz_scene_menu_submenu_callback,
        app);
    submenu_add_item(
        app->submenu,
        "Settings",
        SubmenuIndexSettings,
        flipz_scene_menu_submenu_callback,
        app);

    submenu_set_selected_item(
        app->submenu, scene_manager_get_scene_state(app->scene_manager, FlipZSceneMenu));
    view_dispatcher_switch_to_view(app->view_dispatcher, FlipZViewIdMenu);
}

bool flipz_scene_menu_on_event(void* context, SceneManagerEvent event) {
    FlipZ* app = context;
    if(event.type == SceneManagerEventTypeBack) {
        scene_manager_stop(app->scene_manager);
        view_dispatcher_stop(app->view_dispatcher);
        return true;
    } else if(event.type == SceneManagerEventTypeCustom) {
        uint32_t ct = flipz_coin_type(app);

        if(event.event == SubmenuIndexViewAddr) {
            app->view_mode = FlipZViewModeAddress;
            app->coin_type = ct;
            app->overwrite_saved_seed = 0;
            app->import_from_mnemonic = 0;
            scene_manager_set_scene_state(app->scene_manager, FlipZSceneMenu, event.event);
            scene_manager_next_scene(app->scene_manager, FlipZSceneScene_1);
            return true;
        } else if(event.event == SubmenuIndexGenAddr) {
            app->view_mode = FlipZViewModeGenerate;
            app->coin_type = ct;
            app->overwrite_saved_seed = 0;
            app->import_from_mnemonic = 0;
            scene_manager_set_scene_state(app->scene_manager, FlipZSceneMenu, event.event);
            scene_manager_next_scene(app->scene_manager, FlipZSceneScene_1);
            return true;
        } else if(event.event == SubmenuIndexKeys) {
            app->view_mode = FlipZViewModeKeys;
            app->coin_type = ct;
            app->overwrite_saved_seed = 0;
            app->import_from_mnemonic = 0;
            scene_manager_set_scene_state(app->scene_manager, FlipZSceneMenu, event.event);
            scene_manager_next_scene(app->scene_manager, FlipZSceneScene_1);
            return true;
        } else if(event.event == SubmenuIndexMnemonic) {
            app->view_mode = FlipZViewModeMnemonic;
            app->coin_type = ct;
            app->overwrite_saved_seed = 0;
            app->import_from_mnemonic = 0;
            scene_manager_set_scene_state(app->scene_manager, FlipZSceneMenu, event.event);
            scene_manager_next_scene(app->scene_manager, FlipZSceneScene_1);
            return true;
        } else if(event.event == SubmenuIndexExportFVK) {
            app->view_mode = FlipZViewModeExportFVK;
            app->coin_type = ct;
            app->overwrite_saved_seed = 0;
            app->import_from_mnemonic = 0;
            scene_manager_set_scene_state(app->scene_manager, FlipZSceneMenu, event.event);
            scene_manager_next_scene(app->scene_manager, FlipZSceneScene_1);
            return true;
        } else if(event.event == SubmenuIndexSign) {
            app->view_mode = FlipZViewModeSign;
            app->coin_type = ct;
            app->overwrite_saved_seed = 0;
            app->import_from_mnemonic = 0;
            scene_manager_set_scene_state(app->scene_manager, FlipZSceneMenu, event.event);
            scene_manager_next_scene(app->scene_manager, FlipZSceneScene_1);
            return true;
        } else if(event.event == SubmenuIndexScene1New) {
            /* New wallet → set a PIN first; the Pin scene will route back
             * to scene_1 with overwrite=1 once provisioning completes. */
            app->overwrite_saved_seed = 1;
            app->import_from_mnemonic = 0;
            app->pin_mode = FlipZPinModeProvisionNew;
            app->pin_post_action = FlipZPinPostGenerate;
            scene_manager_set_scene_state(
                app->scene_manager, FlipZSceneMenu, SubmenuIndexScene1New);
            scene_manager_next_scene(app->scene_manager, FlipZScenePin);
            return true;
        } else if(event.event == SubmenuIndexScene1Renew) {
            app->overwrite_saved_seed = 1;
            app->import_from_mnemonic = 0;
            view_dispatcher_switch_to_view(app->view_dispatcher, FlipZViewRenewConfirm);
            return true;
        } else if(event.event == SubmenuIndexWipe) {
            view_dispatcher_switch_to_view(app->view_dispatcher, FlipZViewWipeConfirm);
            return true;
        } else if(event.event == SubmenuIndexScene1Import) {
            /* Import flow → collect PIN first (so the imported mnemonic is
             * sealed). The Pin scene routes to scene_1 with import flag. */
            app->import_from_mnemonic = 1;
            app->pin_mode = FlipZPinModeProvisionNew;
            app->pin_post_action = FlipZPinPostImport;
            scene_manager_set_scene_state(
                app->scene_manager, FlipZSceneMenu, SubmenuIndexScene1Import);
            scene_manager_next_scene(app->scene_manager, FlipZScenePin);
            return true;
        } else if(event.event == SubmenuIndexChangePin) {
            app->pin_mode = FlipZPinModeChangeOld;
            app->pin_post_action = FlipZPinPostMenu;
            scene_manager_next_scene(app->scene_manager, FlipZScenePin);
            return true;
        } else if(event.event == SubmenuIndexSettings) {
            scene_manager_set_scene_state(
                app->scene_manager, FlipZSceneMenu, SubmenuIndexSettings);
            scene_manager_next_scene(app->scene_manager, FlipZSceneSettings);
            return true;
        }
    }
    return false;
}

void flipz_scene_menu_on_exit(void* context) {
    FlipZ* app = context;
    submenu_reset(app->submenu);
}
