#pragma once

/**
 * PIN-protected wallet storage for FlipZcash (audit H-5).
 *
 * Replaces the legacy RC4 wallet.dat layout (now deprecated and explicitly
 * unsafe — RC4 has been broken since 2013 and the K1 was a hardcoded
 * obfuscation constant) with a sealed-blob format using AES-256-CTR +
 * HMAC-SHA256, both provided by libzcash-orchard-c (audit H-3 + H-5).
 *
 * File layout: /ext/apps_data/flipz/wallet.sealed
 *
 *   offset  bytes  field
 *   0       4      magic "ZS01"           (Zcash Sealed v1)
 *   4       16     PBKDF2 salt
 *   20      16     AEAD nonce
 *   36      32     HMAC-SHA256 tag
 *   68      2      ciphertext length (LE)
 *   70      N      ciphertext (sealed mnemonic, up to 240 bytes)
 *
 * Lockout state: /ext/apps_data/flipz/wallet.lockout (32 bytes,
 * wallet_lockout_state_t serialized form). Failure-counter integrity is
 * limited by the FAT filesystem semantics — Flipper Zero has no eFuse-
 * style monotonic counter, so a determined attacker with physical access
 * to the SD card could roll back the counter. The PIN-derived AEAD still
 * resists brute-force at the cryptographic layer (PBKDF2 cost makes
 * offline attacks expensive).
 *
 * Library dependency: aead.h, wallet_lockout.h from libzcash-orchard-c.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#define FLIPZ_PIN_LEN              5    /* match wallet.h ESP32-side */
#define FLIPZ_PIN_KDF_ITERATIONS   50000u  /* ~1s on STM32WB55 @ 64 MHz */
#define FLIPZ_PIN_LOCKOUT_MAX      10u

typedef enum {
    FLIPZ_PIN_OK              = 0,
    FLIPZ_PIN_NOT_INITIALIZED,        /* wallet does not exist yet */
    FLIPZ_PIN_WRONG,                  /* AEAD tag mismatch */
    FLIPZ_PIN_LOCKED_OUT,             /* lockout threshold reached → wipe */
    FLIPZ_PIN_IO_ERROR,
    FLIPZ_PIN_INVALID_INPUT,
} FlipzPinResult;

/** True iff a sealed wallet file exists. */
bool flipz_secure_wallet_exists(void);

/**
 * Provision a fresh wallet: seal the mnemonic + optional BIP-39 passphrase
 * under a PIN-derived key, write to disk. Lockout state is initialised.
 *
 * @param mnemonic     space-separated BIP-39 words
 * @param pin          5-byte PIN, each digit 0..9
 * @param passphrase   NUL-terminated BIP-39 25th word (may be empty)
 */
FlipzPinResult flipz_secure_provision(
    const char* mnemonic,
    const uint8_t pin[FLIPZ_PIN_LEN],
    const char* passphrase);

/**
 * Verify PIN, decrypt mnemonic into the caller's buffer.
 * On wrong PIN, the lockout counter is incremented + persisted; if the
 * threshold is reached, FLIPZ_PIN_LOCKED_OUT is returned and the caller
 * MUST call flipz_secure_wipe() before any further attempt.
 *
 * @param pin              5-byte PIN
 * @param mnemonic_out     buffer for the unsealed mnemonic
 * @param mnemonic_buf_len size of mnemonic_out (must be >= 256)
 */
FlipzPinResult flipz_secure_unlock(
    const uint8_t pin[FLIPZ_PIN_LEN],
    char* mnemonic_out,
    size_t mnemonic_buf_len);

/**
 * Wipe the sealed wallet + lockout state from storage. Irreversible.
 * The caller MUST also wipe any cached keys (FVK/UA blobs) and any
 * device-identity material (M1) per the "full wipe" policy.
 */
void flipz_secure_wipe(void);
