#pragma once

#include <gui/view.h>

/**
 * Tiny shared progress view: header + horizontal bar + label + percentage.
 * Same look as scene_1's PAGE_LOADING but a standalone View so it can be
 * mounted by any scene that needs a "long crypto running" indicator
 * (currently the Pin scene during PBKDF2-driven unlock).
 *
 * Updates are pushed via flipz_progress_set(). Safe to call from any
 * thread — internally guarded by view_dispatcher's locking model.
 */
typedef struct FlipZProgressView FlipZProgressView;

FlipZProgressView* flipz_progress_alloc(void);
void flipz_progress_free(FlipZProgressView* p);
View* flipz_progress_get_view(FlipZProgressView* p);

/** Set the title (top line) — typically static for the duration. */
void flipz_progress_set_title(FlipZProgressView* p, const char* title);

/** Push a new (percent, label) pair. Triggers a redraw. */
void flipz_progress_set(FlipZProgressView* p, uint8_t percent, const char* label);
