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
