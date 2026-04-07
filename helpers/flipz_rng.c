/**
 * Platform RNG for Flipper Zero — provides random32() and random_buffer()
 * using the STM32WB55 hardware RNG via furi_hal.
 */
#include <furi_hal.h>
#include <rand.h>

uint32_t random32(void) {
    return furi_hal_random_get();
}

void random_buffer(uint8_t* buf, size_t len) {
    furi_hal_random_fill_buf(buf, len);
}
