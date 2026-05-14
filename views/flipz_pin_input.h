#pragma once

#include <gui/view.h>
#include <stdint.h>
#include <stdbool.h>

/**
 * Custom 5-digit PIN entry view.
 *
 * Replaces Flipper's stock NumberInput, which clamps the typed value
 * through strtol("12345", ..., 10) and then forces the buffer back to
 * "0" any time the parsed integer is zero — so "0" can't be deleted, a
 * leading-zero PIN is unrepresentable, and the user has to navigate the
 * on-screen keyboard for every digit. We need discrete digit slots that
 * stay in 0..9 and a clean keypress→commit cycle.
 *
 * Controls:
 *   Up / Down   — change the digit at the cursor (wraps 0..9)
 *   Right       — commit current digit, advance cursor; if already on last
 *                 slot, fires the submit callback with the 5-digit array
 *   OK          — same as Right (kept for muscle memory)
 *   Left        — clear the current slot and step the cursor back one
 *   Back        — fires the cancel callback
 */
typedef struct FlipZPinInput FlipZPinInput;

typedef void (*FlipZPinInputSubmitCb)(const uint8_t digits[5], void* context);
typedef void (*FlipZPinInputCancelCb)(void* context);

FlipZPinInput* flipz_pin_input_alloc(void);
void flipz_pin_input_free(FlipZPinInput* p);
View* flipz_pin_input_get_view(FlipZPinInput* p);

/** Set the title shown above the digit boxes. NUL-terminated. */
void flipz_pin_input_set_header(FlipZPinInput* p, const char* header);

/** Reset to all-zero digits, cursor at slot 0. Call before re-displaying
 *  the view for a new PIN entry (e.g. after a wrong-PIN retry). */
void flipz_pin_input_reset(FlipZPinInput* p);

/** Wire up the result callbacks. Either callback may be NULL. */
void flipz_pin_input_set_callbacks(
    FlipZPinInput* p,
    FlipZPinInputSubmitCb on_submit,
    FlipZPinInputCancelCb on_cancel,
    void* context);
