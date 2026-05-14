#pragma once

typedef enum {
    FlipZCustomEventScene1Up,
    FlipZCustomEventScene1Down,
    FlipZCustomEventScene1Left,
    FlipZCustomEventScene1Right,
    FlipZCustomEventScene1Ok,
    FlipZCustomEventScene1Back,
    FlipZCustomEventPinSubmit,   /* number_input save callback fired */
    FlipZCustomEventPinCancel,   /* user pressed Back on PIN entry */
    FlipZCustomEventPinUnlockDone,    /* worker finished unlock (result in app) */
} FlipZCustomEvent;
