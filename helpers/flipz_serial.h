#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

void flipz_serial_init(void);
void flipz_serial_deinit(void);
void flipz_serial_send_raw(const uint8_t* data, size_t len);
void flipz_serial_send(const char* str);

typedef void (*flipz_serial_byte_cb)(uint8_t byte, void* ctx);
size_t flipz_serial_drain(flipz_serial_byte_cb callback, void* ctx);

/* Buffer-based drain used by hwp_dispatcher: pulls up to `out_cap`
 * bytes from the CDC RX buffer in ONE non-blocking read and returns
 * the count actually pulled. Bytes that don't fit stay queued for the
 * next call — this is required for the multi-frame drain handling in
 * hwp_dispatcher, which must back-pressure pulls to one frame at a
 * time. */
size_t flipz_serial_drain_buf(uint8_t* out, size_t out_cap);
