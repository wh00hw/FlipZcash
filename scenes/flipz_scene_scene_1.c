#include "../flipz.h"
#include "../helpers/flipz_custom_event.h"
#include "../views/flipz_scene_1.h"
#include <memzero.h>
#include <string.h>

void flipz_scene_1_callback(FlipZCustomEvent event, void* context) {
    furi_assert(context);
    FlipZ* app = context;
    view_dispatcher_send_custom_event(app->view_dispatcher, event);
}

void flipz_scene_scene_1_on_enter(void* context) {
    furi_assert(context);
    FlipZ* app = context;

    if(app->import_from_mnemonic == 1) {
        // Word-by-word mnemonic import
        app->input_state = FlipZTextInputMnemonic;
        app->import_word_index = 0;
        if(app->bip39_strength == FlipZStrength128)
            app->import_word_count = 12;
        else if(app->bip39_strength == FlipZStrength192)
            app->import_word_count = 18;
        else
            app->import_word_count = 24;
        memzero(app->import_mnemonic_text, TEXT_BUFFER_SIZE);
        snprintf(g_word_header, sizeof(g_word_header), "Word 1/%d", app->import_word_count);
        text_input_set_header_text(app->text_input, g_word_header);
        view_dispatcher_switch_to_view(app->view_dispatcher, FlipZViewIdTextInput);
    } else {
        flipz_scene_1_set_callback(app->flipz_scene_1, flipz_scene_1_callback, app);
        view_dispatcher_switch_to_view(app->view_dispatcher, FlipZViewIdScene1);
    }
}

bool flipz_scene_scene_1_on_event(void* context, SceneManagerEvent event) {
    FlipZ* app = context;
    bool consumed = false;

    if(event.type == SceneManagerEventTypeCustom) {
        switch(event.event) {
        case FlipZCustomEventScene1Back:
            if(!scene_manager_search_and_switch_to_previous_scene(
                   app->scene_manager, FlipZSceneMenu)) {
                scene_manager_stop(app->scene_manager);
                view_dispatcher_stop(app->view_dispatcher);
            }
            consumed = true;
            break;
        }
    }

    return consumed;
}

void flipz_scene_scene_1_on_exit(void* context) {
    FlipZ* app = context;
    UNUSED(app);
}
