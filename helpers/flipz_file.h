#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// --- Simple file helpers (for address, QR, misc) ---
bool flipz_file_exists(const char* file_name);
bool flipz_file_delete(const char* file_name);
bool flipz_file_read(const char* file_name, char* buf, size_t buf_len);
bool flipz_file_write(const char* file_name, const char* data);

bool flipz_save_qrfile(
    const char* qr_msg_prefix,
    const char* qr_msg_content,
    const char* file_name);

// --- Unified wallet.dat ---
bool wallet_exists(void);
bool wallet_delete(void);
bool wallet_save_mnemonic(const char* mnemonic);
bool wallet_load_mnemonic(char* mnemonic_out);
bool wallet_save_keys(
    bool testnet,
    const uint8_t ask[32],
    const uint8_t ak[32],
    const uint8_t nk[32],
    const uint8_t rivk[32]);
bool wallet_load_keys(
    bool testnet,
    uint8_t ask[32],
    uint8_t ak[32],
    uint8_t nk[32],
    uint8_t rivk[32]);
bool wallet_save_testnet(bool testnet);
bool wallet_load_testnet(void);
