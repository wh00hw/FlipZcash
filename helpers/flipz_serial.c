#include "flipz_serial.h"
#include <furi.h>
#include <furi_hal.h>
#include <furi_hal_usb_cdc.h>
#include <cli/cli_vcp.h>
#include <string.h>

#define SERIAL_CH 0
#define CDC_PKT_LEN CDC_DATA_SZ

#define SERIAL_RX_BUF_SIZE 384
static char* s_rx_buf = NULL;
static size_t s_rx_len = 0;
static FuriThread* s_listener_thread = NULL;
static volatile bool s_data_ready = false;

static bool s_cli_was_disabled = false;

static void serial_rx_callback(void* context) {
    UNUSED(context);
    s_data_ready = true;
    if(s_listener_thread) {
        furi_thread_flags_set(furi_thread_get_id(s_listener_thread), 1);
    }
}

static void serial_tx_complete(void* context) {
    UNUSED(context);
}

static void serial_state_cb(void* context, uint8_t state) {
    UNUSED(context);
    UNUSED(state);
}

static const CdcCallbacks s_cdc_cb = {
    serial_tx_complete,
    serial_rx_callback,
    (void (*)(void*, CdcState))serial_state_cb,
    NULL,
    NULL,
};

void flipz_serial_init(void) {
    s_rx_buf = malloc(SERIAL_RX_BUF_SIZE);
    s_rx_len = 0;
    s_data_ready = false;
    s_listener_thread = NULL;

    CliVcp* cli_vcp = furi_record_open(RECORD_CLI_VCP);
    cli_vcp_disable(cli_vcp);
    furi_record_close(RECORD_CLI_VCP);
    s_cli_was_disabled = true;

    furi_hal_usb_unlock();
    furi_check(furi_hal_usb_set_config(&usb_cdc_single, NULL));

    furi_hal_cdc_set_callbacks(SERIAL_CH, (CdcCallbacks*)&s_cdc_cb, NULL);
}

void flipz_serial_deinit(void) {
    furi_hal_cdc_set_callbacks(SERIAL_CH, NULL, NULL);

    if(s_cli_was_disabled) {
        CliVcp* cli_vcp = furi_record_open(RECORD_CLI_VCP);
        cli_vcp_enable(cli_vcp);
        furi_record_close(RECORD_CLI_VCP);
        s_cli_was_disabled = false;
    }

    if(s_rx_buf) {
        free(s_rx_buf);
        s_rx_buf = NULL;
    }
    s_rx_len = 0;
    s_data_ready = false;
    s_listener_thread = NULL;
}

void flipz_serial_send_raw(const uint8_t* data, size_t len) {
    while(len > 0) {
        uint16_t chunk = (len > CDC_PKT_LEN) ? CDC_PKT_LEN : (uint16_t)len;
        furi_hal_cdc_send(SERIAL_CH, (uint8_t*)data, chunk);
        data += chunk;
        len -= chunk;
        furi_delay_ms(3);
    }
}

void flipz_serial_send(const char* str) {
    flipz_serial_send_raw((const uint8_t*)str, strlen(str));
}

size_t flipz_serial_drain(flipz_serial_byte_cb callback, void* ctx) {
    s_listener_thread = furi_thread_get_current();
    size_t total = 0;

    s_data_ready = false;
    uint8_t tmp[CDC_PKT_LEN];
    int32_t len = furi_hal_cdc_receive(SERIAL_CH, tmp, CDC_PKT_LEN);
    while(len > 0) {
        for(int32_t i = 0; i < len; i++) {
            callback(tmp[i], ctx);
            total++;
        }
        len = furi_hal_cdc_receive(SERIAL_CH, tmp, CDC_PKT_LEN);
    }
    return total;
}
