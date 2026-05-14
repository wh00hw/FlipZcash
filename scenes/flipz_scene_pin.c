/**
 * PIN scene: numeric 5-digit entry routed through libzcash's AEAD-sealed
 * wallet helpers (flipz_secure_*).
 *
 * The same scene is reused for unlock, fresh provisioning, and change-PIN.
 * Mode flips via app->pin_mode; the post-action (what to do once provisioning
 * succeeds) is staged in app->pin_post_action so the caller (menu, boot)
 * stays decoupled from the verification machinery.
 */
#include "../flipz.h"
#include "../helpers/flipz_custom_event.h"
#include "../helpers/flipz_file.h"
#include <furi.h>
#include <pbkdf2.h>
#include <memzero.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/*  Async PIN-unlock worker                                            */
/* ------------------------------------------------------------------ */
/* PBKDF2-HMAC-SHA512(50000) is ~1 s on STM32WB55 @ 64 MHz. Running it
 * synchronously inside scene_manager_handle_custom_event blocked the GUI
 * thread (visible UI freeze) and risked overflowing the FAP main-thread
 * stack with the AEAD/PBKDF2 contexts on top of mnemonic[256] staging.
 * The worker isolates that on its own 8 KB stack. */

/* Progress callback invoked from inside libzcash's pbkdf2_hmac_sha512_Update
 * every ~512 iterations. ctx is the FlipZ*, which gives us access to the
 * shared progress view. */
static void pin_pbkdf2_progress(uint8_t pct, const char* label, void* ctx) {
    FlipZ* app = ctx;
    flipz_progress_set(app->progress_view, pct, label);
}

static int32_t pin_unlock_worker(void* ctx) {
    FlipZ* app = ctx;
    memzero(app->pin_worker_mnemonic, sizeof(app->pin_worker_mnemonic));

    /* Hook PBKDF2 → progress view BEFORE running the unlock. Deregister
     * after so other code paths don't accidentally inherit a callback
     * that closes over a stale view pointer. */
    pbkdf2_set_progress_cb(pin_pbkdf2_progress, app);

    app->pin_worker_result = (int)flipz_secure_unlock(
        app->pin_buf,
        app->pin_worker_mnemonic,
        sizeof(app->pin_worker_mnemonic));

    pbkdf2_set_progress_cb(NULL, NULL);

    /* Signal the dispatcher to come pick up the result on the GUI thread. */
    view_dispatcher_send_custom_event(
        app->view_dispatcher, FlipZCustomEventPinUnlockDone);
    return 0;
}

static void start_pin_unlock_worker(FlipZ* app) {
    /* Prime the progress view + switch to it so the user sees the bar
     * starting at 0 % rather than holding the previous PIN-input frame. */
    flipz_progress_set_title(app->progress_view, "Decrypting wallet");
    flipz_progress_set(app->progress_view, 0, "Deriving key");
    view_dispatcher_switch_to_view(app->view_dispatcher, FlipZViewIdLoading);

    if(app->pin_worker) {
        furi_thread_join(app->pin_worker);
        furi_thread_free(app->pin_worker);
        app->pin_worker = NULL;
    }
    app->pin_worker = furi_thread_alloc_ex("ZcashUnlock", 8192,
                                            pin_unlock_worker, app);
    furi_thread_start(app->pin_worker);
}

static const char* pin_header_for_mode(int mode) {
    switch(mode) {
    case FlipZPinModeUnlock:           return "Enter PIN to unlock";
    case FlipZPinModeProvisionNew:     return "Set new PIN (5 digits)";
    case FlipZPinModeProvisionConfirm: return "Confirm PIN";
    case FlipZPinModeChangeOld:        return "Enter current PIN";
    case FlipZPinModeChangeNew:        return "Set new PIN";
    case FlipZPinModeChangeConfirm:    return "Confirm new PIN";
    default:                           return "PIN";
    }
}

static void pin_input_submit_cb(const uint8_t digits[5], void* context) {
    FlipZ* app = context;
    /* Stage the digits directly into pin_buf so the on_event handler can
     * read them as it always has. memcpy is safe — both buffers are 5 B. */
    memcpy(app->pin_buf, digits, FLIPZ_PIN_LEN);
    view_dispatcher_send_custom_event(app->view_dispatcher, FlipZCustomEventPinSubmit);
}

static void pin_input_cancel_cb(void* context) {
    FlipZ* app = context;
    view_dispatcher_send_custom_event(app->view_dispatcher, FlipZCustomEventPinCancel);
}

/* `default_value` is currently unused but kept in the signature for
 * symmetry with the previous NumberInput-based show_pin_input — drops in
 * future flows that want to pre-populate digits (e.g. dev defaults). */
static void show_pin_input(FlipZ* app, int32_t default_value) {
    (void)default_value;
    flipz_pin_input_set_header(app->pin_input, pin_header_for_mode(app->pin_mode));
    flipz_pin_input_reset(app->pin_input);
    flipz_pin_input_set_callbacks(
        app->pin_input, pin_input_submit_cb, pin_input_cancel_cb, app);
    view_dispatcher_switch_to_view(app->view_dispatcher, FlipZViewIdPinInput);
}

void flipz_scene_pin_on_enter(void* context) {
    FlipZ* app = context;
    show_pin_input(app, 0);
}

/* ------------------------------------------------------------------ */
/*  Mode handlers                                                      */
/* ------------------------------------------------------------------ */

static void handle_unlock_submit(FlipZ* app) {
    /* pin_buf is already populated by the custom view's submit cb. Hand
     * the heavy crypto to the worker; on completion it sends
     * FlipZCustomEventPinUnlockDone which we consume below. */
    start_pin_unlock_worker(app);
}

static void handle_unlock_done(FlipZ* app, bool route_to_change_new) {
    /* Worker is finished; result + plaintext mnemonic are in
     * pin_worker_result / pin_worker_mnemonic. Whatever path runs, scrub
     * the staging buffer before returning. */
    FlipzPinResult r = (FlipzPinResult)app->pin_worker_result;

    if(app->pin_worker) {
        furi_thread_join(app->pin_worker);
        furi_thread_free(app->pin_worker);
        app->pin_worker = NULL;
    }

    if(r == FLIPZ_PIN_OK) {
        memcpy(app->cached_mnemonic,
               app->pin_worker_mnemonic,
               sizeof(app->cached_mnemonic));
        memzero(app->pin_worker_mnemonic, sizeof(app->pin_worker_mnemonic));
        memzero(app->pin_buf, FLIPZ_PIN_LEN);
        app->is_unlocked = true;

        if(route_to_change_new) {
            /* Change-PIN flow: old PIN verified, now collect the new one. */
            app->pin_mode = FlipZPinModeChangeNew;
            show_pin_input(app, 0);
            return;
        }

        /* Pop ourselves and reveal Menu (boot pushed Menu first, then Pin
         * on top, so Menu is on the stack below us). The scene manager
         * fires Menu's on_enter on reveal, which now resets the submenu
         * before re-adding items — no duplicate-row regression. */
        scene_manager_search_and_switch_to_previous_scene(
            app->scene_manager, FlipZSceneMenu);
        return;
    }

    memzero(app->pin_worker_mnemonic, sizeof(app->pin_worker_mnemonic));
    memzero(app->pin_buf, FLIPZ_PIN_LEN);

    if(r == FLIPZ_PIN_LOCKED_OUT) {
        flipz_full_wipe(app);
        scene_manager_search_and_switch_to_previous_scene(
            app->scene_manager, FlipZSceneMenu);
        return;
    }

    /* Wrong PIN (or IO/init error treated as a recoverable miss): refresh
     * the input view so the user can retry. */
    show_pin_input(app, 0);
}

static void provision_seal_with_current_pin(FlipZ* app) {
    /* Use the cached mnemonic if we already have it (change-PIN flow); else
     * read it from sealed (with old PIN, but we have the bytes here only
     * during change). For fresh provisioning the caller seeds
     * cached_mnemonic before pushing the scene. */
    const char* mn = app->cached_mnemonic[0] ? app->cached_mnemonic : NULL;
    if(!mn) return;
    const char* pp = (app->passphrase == FlipZPassphraseOn &&
                      app->passphrase_text[0]) ? app->passphrase_text : "";
    flipz_secure_provision(mn, app->pin_buf, pp);
    /* Drop legacy plaintext-RC4 wallet.dat — it would otherwise be read in
     * preference to the sealed file by anyone using flipz_get_mnemonic with
     * a fallback path. Keys cache stays (regenerable on next unlock). */
    wallet_delete();
    memzero(app->pin_buf, FLIPZ_PIN_LEN);
    memzero(app->pin_confirm_buf, FLIPZ_PIN_LEN);
    app->is_unlocked = true;  /* mnemonic is already in cache */
}

static void handle_provision_submit(FlipZ* app) {
    /* pin_buf is already populated by the custom view's submit cb. */

    if(app->pin_mode == FlipZPinModeProvisionNew ||
       app->pin_mode == FlipZPinModeChangeNew) {
        memcpy(app->pin_confirm_buf, app->pin_buf, FLIPZ_PIN_LEN);
        memzero(app->pin_buf, FLIPZ_PIN_LEN);
        app->pin_mode = (app->pin_mode == FlipZPinModeProvisionNew)
                            ? FlipZPinModeProvisionConfirm
                            : FlipZPinModeChangeConfirm;
        show_pin_input(app, 0);
        return;
    }

    /* Confirm step: compare; on mismatch restart from "new". */
    bool match = (memcmp(app->pin_buf, app->pin_confirm_buf, FLIPZ_PIN_LEN) == 0);
    memzero(app->pin_confirm_buf, FLIPZ_PIN_LEN);
    if(!match) {
        memzero(app->pin_buf, FLIPZ_PIN_LEN);
        app->pin_mode = (app->pin_mode == FlipZPinModeProvisionConfirm)
                            ? FlipZPinModeProvisionNew
                            : FlipZPinModeChangeNew;
        show_pin_input(app, 0);
        return;
    }

    if(app->pin_mode == FlipZPinModeChangeConfirm) {
        provision_seal_with_current_pin(app);
        scene_manager_search_and_switch_to_previous_scene(
            app->scene_manager, FlipZSceneMenu);
        return;
    }

    /* ProvisionConfirm path: route to the post-action requested by the
     * caller. The actual mnemonic generation/import happens in scene_1
     * which now reads pin_buf to seal whatever it produces. */
    switch(app->pin_post_action) {
    case FlipZPinPostGenerate:
        app->view_mode = FlipZViewModeGenerate;
        app->coin_type = flipz_coin_type(app);
        app->overwrite_saved_seed = 1;
        app->import_from_mnemonic = 0;
        scene_manager_next_scene(app->scene_manager, FlipZSceneScene_1);
        break;
    case FlipZPinPostImport:
        app->import_from_mnemonic = 1;
        scene_manager_next_scene(app->scene_manager, FlipZSceneScene_1);
        break;
    case FlipZPinPostMenu:
    default:
        scene_manager_search_and_switch_to_previous_scene(
            app->scene_manager, FlipZSceneMenu);
        break;
    }
}

static void handle_change_old_submit(FlipZ* app) {
    /* pin_buf populated by the custom view. Same async path as boot
     * unlock; the on_event handler distinguishes "route to ChangeNew vs
     * Menu" via app->pin_mode. */
    start_pin_unlock_worker(app);
}

/* ------------------------------------------------------------------ */
/*  Scene handlers                                                     */
/* ------------------------------------------------------------------ */

bool flipz_scene_pin_on_event(void* context, SceneManagerEvent event) {
    FlipZ* app = context;
    if(event.type != SceneManagerEventTypeCustom) return false;

    if(event.event == FlipZCustomEventPinCancel) {
        memzero(app->pin_buf, FLIPZ_PIN_LEN);
        memzero(app->pin_confirm_buf, FLIPZ_PIN_LEN);
        scene_manager_search_and_switch_to_previous_scene(
            app->scene_manager, FlipZSceneMenu);
        return true;
    }

    if(event.event == FlipZCustomEventPinUnlockDone) {
        /* The mode at the time of submit determines what to do on success:
         * Unlock → return to menu; ChangeOld → advance to ChangeNew. */
        bool route_to_change_new = (app->pin_mode == FlipZPinModeChangeOld);
        handle_unlock_done(app, route_to_change_new);
        return true;
    }

    if(event.event != FlipZCustomEventPinSubmit) return false;

    switch(app->pin_mode) {
    case FlipZPinModeUnlock:
        handle_unlock_submit(app);
        break;
    case FlipZPinModeProvisionNew:
    case FlipZPinModeProvisionConfirm:
    case FlipZPinModeChangeNew:
    case FlipZPinModeChangeConfirm:
        handle_provision_submit(app);
        break;
    case FlipZPinModeChangeOld:
        handle_change_old_submit(app);
        break;
    }
    return true;
}

void flipz_scene_pin_on_exit(void* context) {
    FlipZ* app = context;
    /* Furi's scene_manager_next_scene() fires on_exit BEFORE the new
     * scene's on_enter runs (scene_manager.c:102). The Pin → Scene_1
     * provisioning hand-off relies on pin_buf surviving that
     * transition: the Scene_1 worker reads it, calls
     * flipz_secure_provision, then zeros it itself. So we must NOT
     * scrub pin_buf here, otherwise the seal happens with all-zero
     * PIN and the user can never unlock again.
     *
     * pin_confirm_buf is fine to wipe — its only legitimate use is the
     * stage-1→stage-2 comparison and that's already complete by the
     * time on_exit fires. cached_mnemonic stays — the next scene
     * (Scene_1 / Menu) needs it for derivation / display.
     *
     * The legitimate scrubbing sites for pin_buf are:
     *   - Pin scene's Cancel handler (user backed out)
     *   - Pin scene's wrong-PIN retry path
     *   - handle_unlock_done() on success
     *   - sign/gen worker after consuming the PIN
     *   - flipz_full_wipe() (explicit user wipe) and flipz_app_free(). */
    memzero(app->pin_confirm_buf, FLIPZ_PIN_LEN);
}
