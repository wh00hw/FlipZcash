#include "flipz_pin_input.h"
#include <gui/elements.h>
#include <input/input.h>
#include <string.h>

#define PIN_LEN          5
#define HEADER_MAX_LEN   28

typedef struct {
    uint8_t digits[PIN_LEN];
    bool    entered[PIN_LEN];
    uint8_t cursor;
    char    header[HEADER_MAX_LEN];
} FlipZPinInputModel;

struct FlipZPinInput {
    View* view;
    FlipZPinInputSubmitCb on_submit;
    FlipZPinInputCancelCb on_cancel;
    void* context;
};

/* ------------------------------------------------------------------ */
/*  Drawing                                                            */
/* ------------------------------------------------------------------ */

static void flipz_pin_input_draw(Canvas* canvas, void* m) {
    FlipZPinInputModel* model = m;
    canvas_clear(canvas);
    canvas_set_color(canvas, ColorBlack);

    /* Header line */
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str_aligned(
        canvas, 64, 4, AlignCenter, AlignTop, model->header);

    /* Five digit boxes, 18 px wide × 22 px tall, centered. The 128-px
     * screen fits 5*18 + 4*4 (gaps) = 106 px → margin = (128-106)/2 = 11 px. */
    const int box_w = 18;
    const int box_h = 22;
    const int gap   = 4;
    const int total = PIN_LEN * box_w + (PIN_LEN - 1) * gap;
    const int x0    = (128 - total) / 2;
    const int y0    = 18;

    canvas_set_font(canvas, FontBigNumbers);
    for(int i = 0; i < PIN_LEN; i++) {
        int x = x0 + i * (box_w + gap);
        elements_slightly_rounded_frame(canvas, x, y0, box_w, box_h);
        if(model->entered[i]) {
            char d = '0' + (model->digits[i] % 10);
            char s[2] = {d, '\0'};
            canvas_draw_str_aligned(
                canvas, x + box_w / 2, y0 + box_h / 2 + 1,
                AlignCenter, AlignCenter, s);
        }
        /* Underline the cursor slot so the user sees which one Up/Down
         * is editing — purely visual, the model carries the truth. */
        if(i == model->cursor) {
            canvas_draw_line(canvas, x + 2, y0 + box_h + 1,
                             x + box_w - 2, y0 + box_h + 1);
            canvas_draw_line(canvas, x + 2, y0 + box_h + 2,
                             x + box_w - 2, y0 + box_h + 2);
        }
    }

    /* Footer hint */
    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str_aligned(
        canvas, 64, 56, AlignCenter, AlignTop,
        "OK/\xC2\xBB next  \xC2\xAB del  \xE2\x86\x91\xE2\x86\x93 digit");
    /* That hint string is "OK/» next  « del  ↑↓ digit" in UTF-8. The
     * Flipper canvas font supports the Latin-1 supplement and a small
     * arrow set; if a glyph misses the device just shows '?'. */
}

/* ------------------------------------------------------------------ */
/*  Input handling                                                     */
/* ------------------------------------------------------------------ */

static void submit_pin(FlipZPinInput* p, FlipZPinInputModel* model) {
    /* Any unentered slot is treated as zero — matches user expectation
     * that pressing OK on the last slot accepts the visible digits. */
    uint8_t digits[PIN_LEN];
    for(int i = 0; i < PIN_LEN; i++) digits[i] = model->digits[i];
    if(p->on_submit) p->on_submit(digits, p->context);
}

static bool flipz_pin_input_input_cb(InputEvent* event, void* context) {
    FlipZPinInput* p = context;

    /* Only handle on Press / Repeat to support hold-to-scroll on Up/Down,
     * so the user can spin a digit without bouncing the key. We send
     * Submit on Press (immediate response feels right for the OK key). */
    if(event->type != InputTypePress && event->type != InputTypeRepeat) {
        return false;
    }

    bool submit_now = false;

    with_view_model(
        p->view,
        FlipZPinInputModel * model,
        {
            switch(event->key) {
            case InputKeyUp:
                model->digits[model->cursor] =
                    (uint8_t)((model->digits[model->cursor] + 1) % 10);
                model->entered[model->cursor] = true;
                break;
            case InputKeyDown:
                model->digits[model->cursor] =
                    (uint8_t)((model->digits[model->cursor] + 9) % 10);
                model->entered[model->cursor] = true;
                break;
            case InputKeyRight:
            case InputKeyOk:
                /* Mark the current slot as entered (default 0 if untouched)
                 * then advance, or submit on the last slot. */
                model->entered[model->cursor] = true;
                if(model->cursor < PIN_LEN - 1) {
                    model->cursor++;
                } else {
                    submit_now = true;
                }
                break;
            case InputKeyLeft:
                /* Clear the current slot and step back one. If we're on
                 * slot 0, just clear it (don't underflow). */
                model->digits[model->cursor]  = 0;
                model->entered[model->cursor] = false;
                if(model->cursor > 0) model->cursor--;
                break;
            case InputKeyBack:
                /* Bubble cancel — the scene decides what to do. */
                if(p->on_cancel && event->type == InputTypePress) {
                    /* Defer the callback until we've released the model. */
                }
                break;
            default:
                break;
            }
        },
        true);

    if(event->key == InputKeyBack && event->type == InputTypePress) {
        if(p->on_cancel) p->on_cancel(p->context);
        return true;
    }

    if(submit_now) {
        FlipZPinInputModel* unused;
        (void)unused;
        with_view_model(
            p->view,
            FlipZPinInputModel * model,
            { submit_pin(p, model); },
            false);
    }
    return true;
}

/* ------------------------------------------------------------------ */
/*  Public API                                                         */
/* ------------------------------------------------------------------ */

FlipZPinInput* flipz_pin_input_alloc(void) {
    FlipZPinInput* p = malloc(sizeof(FlipZPinInput));
    if(!p) return NULL;
    p->view = view_alloc();
    p->on_submit = NULL;
    p->on_cancel = NULL;
    p->context   = NULL;
    view_set_context(p->view, p);
    view_allocate_model(p->view, ViewModelTypeLocking, sizeof(FlipZPinInputModel));
    view_set_draw_callback(p->view, flipz_pin_input_draw);
    view_set_input_callback(p->view, flipz_pin_input_input_cb);

    with_view_model(
        p->view,
        FlipZPinInputModel * model,
        {
            memset(model->digits, 0, sizeof(model->digits));
            memset(model->entered, 0, sizeof(model->entered));
            model->cursor = 0;
            model->header[0] = '\0';
        },
        true);
    return p;
}

void flipz_pin_input_free(FlipZPinInput* p) {
    if(!p) return;
    view_free(p->view);
    free(p);
}

View* flipz_pin_input_get_view(FlipZPinInput* p) { return p->view; }

void flipz_pin_input_set_header(FlipZPinInput* p, const char* header) {
    if(!p || !header) return;
    with_view_model(
        p->view,
        FlipZPinInputModel * model,
        {
            size_t n = 0;
            while(header[n] && n < sizeof(model->header) - 1) {
                model->header[n] = header[n];
                n++;
            }
            model->header[n] = '\0';
        },
        true);
}

void flipz_pin_input_reset(FlipZPinInput* p) {
    if(!p) return;
    with_view_model(
        p->view,
        FlipZPinInputModel * model,
        {
            memset(model->digits, 0, sizeof(model->digits));
            memset(model->entered, 0, sizeof(model->entered));
            model->cursor = 0;
        },
        true);
}

void flipz_pin_input_set_callbacks(
    FlipZPinInput* p,
    FlipZPinInputSubmitCb on_submit,
    FlipZPinInputCancelCb on_cancel,
    void* context) {
    if(!p) return;
    p->on_submit = on_submit;
    p->on_cancel = on_cancel;
    p->context   = context;
}
