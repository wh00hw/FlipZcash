#include "../flipz.h"
#include "../helpers/flipz_file.h"
#include <string.h>

void flipz_scene_menu_submenu_callback(void* context, uint32_t index) {
    furi_assert(context);
    FlipZ* app = context;
    view_dispatcher_send_custom_event(app->view_dispatcher, index);
}

void flipz_scene_menu_on_enter(void* context) {
    FlipZ* app = context;

    bool has_wallet = wallet_exists();

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
            "Regenerate wallet",
            SubmenuIndexScene1Renew,
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
            app->overwrite_saved_seed = 1;
            app->import_from_mnemonic = 0;
            app->wallet_create(app);
            return true;
        } else if(event.event == SubmenuIndexScene1Renew) {
            app->overwrite_saved_seed = 1;
            app->import_from_mnemonic = 0;
            view_dispatcher_switch_to_view(app->view_dispatcher, FlipZViewRenewConfirm);
            return true;
        } else if(event.event == SubmenuIndexScene1Import) {
            app->import_from_mnemonic = 1;
            scene_manager_set_scene_state(
                app->scene_manager, FlipZSceneMenu, SubmenuIndexScene1Import);
            scene_manager_next_scene(app->scene_manager, FlipZSceneScene_1);
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
