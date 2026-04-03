#pragma once

#include <gui/view.h>
#include "../helpers/flipz_custom_event.h"

typedef struct FlipZScene1 FlipZScene1;

typedef void (*FlipZScene1Callback)(FlipZCustomEvent event, void* context);

void flipz_scene_1_set_callback(
    FlipZScene1* flipz_scene_1,
    FlipZScene1Callback callback,
    void* context);

View* flipz_scene_1_get_view(FlipZScene1* flipz_static);

FlipZScene1* flipz_scene_1_alloc();

void flipz_scene_1_free(FlipZScene1* flipz_static);
