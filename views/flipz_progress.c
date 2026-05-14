#include "flipz_progress.h"
#include <gui/elements.h>
#include <stdio.h>
#include <string.h>

#define FLIPZ_PROGRESS_LABEL_MAX 32
#define FLIPZ_PROGRESS_TITLE_MAX 24

typedef struct {
    char title[FLIPZ_PROGRESS_TITLE_MAX];
    char label[FLIPZ_PROGRESS_LABEL_MAX];
    uint8_t percent;
} FlipZProgressModel;

struct FlipZProgressView {
    View* view;
};

static void flipz_progress_draw(Canvas* canvas, void* m) {
    FlipZProgressModel* model = m;

    canvas_clear(canvas);
    canvas_set_color(canvas, ColorBlack);

    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 2, 10, model->title);

    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str(canvas, 2, 24, model->label);

    /* Bar frame: same geometry as scene_1's PAGE_LOADING for visual
     * consistency between the two long-crypto screens. */
    canvas_draw_frame(canvas, 2, 34, 124, 10);
    uint8_t fill = (uint8_t)((uint32_t)model->percent * 120u / 100u);
    if(fill > 0) canvas_draw_box(canvas, 4, 36, fill, 6);

    char pct_text[8];
    snprintf(pct_text, sizeof(pct_text), "%u%%", (unsigned)model->percent);
    canvas_draw_str_aligned(canvas, 64, 52, AlignCenter, AlignTop, pct_text);
}

FlipZProgressView* flipz_progress_alloc(void) {
    FlipZProgressView* p = malloc(sizeof(FlipZProgressView));
    if(!p) return NULL;
    p->view = view_alloc();
    view_allocate_model(p->view, ViewModelTypeLocking, sizeof(FlipZProgressModel));
    view_set_draw_callback(p->view, flipz_progress_draw);

    /* Sensible defaults so a freshly-mounted view shows something
     * coherent before the first set() call lands. */
    with_view_model(
        p->view,
        FlipZProgressModel * model,
        {
            strncpy(model->title, "Working...", sizeof(model->title) - 1);
            model->title[sizeof(model->title) - 1] = '\0';
            model->label[0] = '\0';
            model->percent = 0;
        },
        true);
    return p;
}

void flipz_progress_free(FlipZProgressView* p) {
    if(!p) return;
    view_free(p->view);
    free(p);
}

View* flipz_progress_get_view(FlipZProgressView* p) {
    return p->view;
}

void flipz_progress_set_title(FlipZProgressView* p, const char* title) {
    if(!p || !title) return;
    with_view_model(
        p->view,
        FlipZProgressModel * model,
        {
            strncpy(model->title, title, sizeof(model->title) - 1);
            model->title[sizeof(model->title) - 1] = '\0';
        },
        true);
}

void flipz_progress_set(FlipZProgressView* p, uint8_t percent, const char* label) {
    if(!p) return;
    with_view_model(
        p->view,
        FlipZProgressModel * model,
        {
            model->percent = percent > 100 ? 100 : percent;
            if(label) {
                strncpy(model->label, label, sizeof(model->label) - 1);
                model->label[sizeof(model->label) - 1] = '\0';
            }
        },
        true);
}
