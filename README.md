# FlipZcash — Zcash Orchard Shielded Wallet for Flipper Zero

> **WARNING: This is a proof-of-concept. It has NOT been audited. Do not use with real funds.**

FlipZcash is a Zcash Orchard shielded wallet running entirely on the Flipper Zero. It can generate shielded addresses, display them as QR codes, and sign transactions via USB serial — all using the Flipper's constrained hardware (STM32WB55, 64 MHz ARM Cortex-M4, 256 KB RAM).

## Origin

This project started as an experiment to see if Zcash Orchard cryptography (Pallas curve, Sinsemilla hash, RedPallas signatures) could run on the Flipper Zero's limited hardware.

The first Orchard address generation on a Flipper Zero:
https://x.com/nic_whr/status/2037306755844018441

The first shielded transaction propagated from a Flipper Zero:
https://x.com/nic_whr/status/2038744292336849279

## Acknowledgments

The BIP39 mnemonic implementation and the overall Flipper Zero app architecture (scene manager, view dispatcher, encrypted storage) are based on [FlipBIP](https://github.com/xtruan/FlipBIP) by xtruan, to which I am a contributor.

## Dependencies

FlipZcash relies on two companion libraries, both purpose-built for this project:

- **[libzcash-orchard-c](https://github.com/wh00hw/libzcash-orchard-c)** (git submodule) — Pure C implementation of Zcash Orchard cryptography: Pallas curve arithmetic, Sinsemilla hash, RedPallas signatures, ZIP-32 key derivation, FF1-AES-256, F4Jumble, BIP39, ZIP-244 sighash computation, and the `OrchardSigner` state machine for on-device sighash verification. Portable across embedded targets.

- **[zcash-hw-wallet-sdk](https://github.com/wh00hw/zcash-hw-wallet-sdk)** — Rust SDK implementing the Hardware Wallet Protocol (HWP v2), the binary framed serial protocol used for communication between the Flipper Zero and the companion broadcast app. Handles PCZT parsing, Orchard proof generation, staged sighash verification, and signature collection.

## Features

- **Generate wallet** — BIP39 mnemonic (12/18/24 words) with optional passphrase
- **Import wallet** — Word-by-word mnemonic entry with autocomplete
- **Shielded address** — Orchard Unified Address with QR code display
- **USB Serial Signer** — Sign transactions via HWP v2 protocol with on-device confirmation (recipient, amount, fee)
- **ZIP-244 sighash verification** — On-device staged verification: the companion sends transaction metadata and action data individually, the device hashes them incrementally using ZIP-244, and compares the computed sighash against the companion's before allowing any signature
- **Key export** — Full Viewing Key (ak, nk, rivk) for watch-only wallets
- **Mainnet/Testnet** — Switch between ZEC and TAZ networks
- **Encrypted storage** — Mnemonic encrypted on SD card with RC4 (K1/K2 scheme)
- **Hardware RNG** — Uses the STM32WB55 true random number generator for all cryptographic randomness

## Signing Protocol (HWP v2)

The signing flow implements the staged sighash verification protocol defined by `zcash-hw-wallet-sdk`:

1. **Handshake** — Device sends PING, companion replies PONG
2. **FVK export** — Companion requests Full Viewing Key for wallet pairing
3. **Staged verification** — Companion sends transaction data for on-device ZIP-244 sighash computation:
   - `TX_OUTPUT(0xFFFF, N, metadata)` — Transaction header (125 bytes: version, branch ID, lock time, expiry, orchard flags, value balance, anchor, transparent/sapling digests)
   - `TX_OUTPUT(i, N, action_data)` × N — Each Orchard action (820 bytes: cv_net, nullifier, rk, cmx, ephemeral_key, enc_ciphertext, out_ciphertext)
   - `TX_OUTPUT(N, N, sighash)` — Sentinel with expected sighash for comparison
4. **User confirmation** — Device displays recipient, amount, fee; user approves or cancels
5. **Signing** — `SIGN_REQ` → `orchard_signer_sign()` (enforces verification invariant) → `SIGN_RSP`

The `OrchardSignerCtx` state machine in libzcash-orchard-c guarantees at the library level that signatures cannot be produced without completing ZIP-244 verification first.

## Sinsemilla Lookup Table

The first time you generate an address, Orchard key derivation involves heavy elliptic curve math (Sinsemilla hash) that takes **~15 minutes** on the Flipper's hardware.

You can reduce this to **~1.5 minutes** by copying a precomputed lookup table to the SD card:

1. Copy `sinsemilla_s.bin` (64 KB) to:
   ```
   SD Card/apps_data/flipz/sinsemilla_s.bin
   ```

2. The file contains 1024 precomputed Pallas curve points (64 bytes each: x || y, little-endian).
   Each point is verifiable: `S_i = hash_to_curve("z.cash:SinsemillaS")(i.to_le_bytes())` for i in 0..1024.

Subsequent launches use the cached address and skip derivation entirely.

## Building

Requires the [Unleashed Firmware](https://github.com/DarkFlippers/unleashed-firmware) toolchain:

```bash
# Clone with submodules
git clone --recurse-submodules https://github.com/wh00hw/FlipZcash.git

# Symlink into the firmware
ln -s /path/to/FlipZcash /path/to/unleashed-firmware/applications_user/FlipZcash

# Build
cd /path/to/unleashed-firmware
./fbt fap_flipz

# Install and launch on connected Flipper
./fbt launch APPSRC=applications_user/FlipZcash
```

The compiled `.fap` will be at `build/f7-firmware-D/.extapps/flipz.fap`.

## Project Structure

```
FlipZcash/
  application.fam          App manifest
  flipz.h / flipz.c        App entry point, scene dispatch
  flipz_coins.h / .c        Coin type definitions (ZEC/TAZ)
  helpers/
    flipz_file.*            Encrypted wallet storage (wallet.dat)
    flipz_string.*          Hex conversion, RC4 cipher
    flipz_serial.*          USB CDC serial communication
    flipz_rng.c             Hardware RNG bridge (STM32WB55 → libzcash)
    flipz_custom_event.h    Input event definitions
  scenes/
    flipz_scene_menu.c      Main menu
    flipz_scene_settings.c  Network, BIP39 strength, passphrase
    flipz_scene_scene_1.c   Scene dispatcher for views
  views/
    flipz_scene_1.*         Address generation, key display, serial signer
  lib/
    zcash/                  libzcash-orchard-c (git submodule)
    qrcode/                 QR code generation (qrcodegen)
```

## Disclaimer

This software is a **proof-of-concept** born from an experimental exploration of Zcash Orchard on embedded hardware. It has **not been audited** by any security firm. The cryptographic primitives were implemented from scratch in C and, while tested against official test vectors, may contain subtle bugs.

**Do not use this software to manage real funds.** Use at your own risk.

## License

MIT
