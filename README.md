# FlipZcash — Zcash Orchard Shielded Wallet for Flipper Zero

> **WARNING: This is a proof-of-concept. It has NOT been audited.**

FlipZcash is a Zcash Orchard shielded wallet running entirely on the Flipper Zero. It can generate shielded addresses, display them as QR codes, and sign transactions via USB serial — all using the Flipper's constrained hardware (STM32WB55, 64 MHz ARM Cortex-M4, 256 KB RAM).

## Origin

This project started as an experiment to see if Zcash Orchard cryptography (Pallas curve, Sinsemilla hash, RedPallas signatures) could run on the Flipper Zero's limited hardware.

The first Orchard address generation on a Flipper Zero:
https://x.com/nic_whr/status/2037306755844018441

The first shielded transaction propagated from a Flipper Zero:
https://x.com/nic_whr/status/2038744292336849279

## Mainnet Broadcast

The first ever Zcash mainnet Orchard-shielded spend signed offline by a Flipper Zero hardware wallet was broadcast on **2026-03-30**:

| Field | Value |
|---|---|
| **Transaction hash** | `1c9eb6ca4ada67bf66452120d128ceacf2c0e21146de089e51694eb14db5466b` |
| **Wallet birthday** | Zcash block height `3290915` |
| **Network** | Zcash mainnet (`coin_type = 133`) |
| **Pool** | Orchard shielded |
| **Memo** | "First ever Zcash shielded TX signed offline by a Flipper Zero hardware wallet. Air-gapped, private, unstoppable. — wh00hw" |

Captured evidence (in this repository):

- [`screenshots/mainnet_pair.png`](screenshots/mainnet_pair.png) — `zipher-cli wallet pair-hardware --port /dev/ttyACM0 --birthday 3290915` succeeding (FVK exported from the Flipper, watch-only wallet imported into the companion).
- [`screenshots/mainnet_broadcast.png`](screenshots/mainnet_broadcast.png) — full terminal session ending with `Transaction broadcast! TxID: 1c9eb6ca…5466b`.
- [`screenshots/memo.png`](screenshots/memo.png) — Cypherscan "Decrypt Shielded Memo" view corroborating the same TxID and rendering the decrypted memo.

For the full technical specification — primitives, derivation pipeline,
HWP wire protocol, on-device sighash verification state machine, performance
numbers, and security model — see [`IMPLEMENTATION.md`](IMPLEMENTATION.md).

## Architecture

FlipZcash uses a **delegated-signing** model. The signing work is split between
the device and a companion application (the Rust SDK
[`zcash-hw-wallet-sdk`](https://github.com/wh00hw/zcash-hw-wallet-sdk),
typically driven by `zipher-cli`):

```
┌──────────────────────┐                    ┌──────────────────────────┐
│     Flipper Zero     │                    │     Companion App        │
│                      │                    │                          │
│  Holds:              │   FVK export       │   Holds: FVK             │
│  - ask  (NEVER       │ ─────────────────> │     (ak, nk, rivk)       │
│         leaves)      │                    │   (watch-only)           │
│  - nk, rivk, fvk     │   HWP frames       │                          │
│  - transparent SK    │ <───────────────── │   Does:                  │
│    (session-cached)  │                    │   - blockchain sync      │
│                      │   sighash + alpha  │   - PCZT construction    │
│  Does:               │ <───────────────── │   - Halo2 proof gen      │
│  - on-device ZIP-244 │                    │   - signature injection  │
│    sighash verify    │   sig + rk         │   - broadcast            │
│  - user confirmation │ ─────────────────> │                          │
│  - RedPallas signing │                    │                          │
│  - secp256k1 ECDSA   │                    │                          │
│    (transparent)     │                    │                          │
└──────────────────────┘                    └──────────────────────────┘
```

The spending key `ask` never leaves the device. The companion only ever
holds the Full Viewing Key, which lets it watch the chain and assemble
transactions but cannot authorize a spend. In Orchard, only the RedPallas
spend-authorization signature requires `ask`; everything else (Halo2 proof,
nullifier derivation, value commitment, note encryption, binding signature)
can be computed from the FVK.

On-device sighash verification is enforced as a library invariant:
`orchard_signer_sign()` in `lib/libzcash-orchard-c/src/orchard_signer.c`
refuses to run unless the device has independently recomputed the
ZIP-244 sighash from the streamed action data and matched it against the
companion's expected value. A buggy or hostile firmware port cannot bypass
the check because it lives in the C library, not in device-specific code.

## Acknowledgments

The BIP39 mnemonic implementation and the overall Flipper Zero app architecture (scene manager, view dispatcher, encrypted storage) are based on [FlipBIP](https://github.com/xtruan/FlipBIP) by xtruan, to which I am a contributor.

## Dependencies

FlipZcash relies on two companion libraries, both purpose-built for this project:

- **[libzcash-orchard-c](https://github.com/wh00hw/libzcash-orchard-c)** (git submodule) — Pure C implementation of Zcash cryptography: Pallas curve arithmetic, Sinsemilla hash, RedPallas signatures, ZIP-32 key derivation, FF1-AES-256, F4Jumble, BIP-39, BIP-32, secp256k1 + ECDSA (RFC 6979), full ZIP-244 sighash computation (shielded and transparent txid digests + per-input sig digest), and the `OrchardSigner` state machine for on-device sighash verification. Portable across embedded targets.

- **[zcash-hw-wallet-sdk](https://github.com/wh00hw/zcash-hw-wallet-sdk)** — Rust SDK implementing the Hardware Wallet Protocol (HWP v3), the binary framed serial protocol used for communication between the Flipper Zero and the companion broadcast app. Handles PCZT parsing, Orchard proof generation, staged sighash verification for both shielded and transparent bundles, and signature collection (RedPallas + ECDSA).

## Features

- **Generate wallet** — BIP-39 mnemonic (12/18/24 words) with optional passphrase
- **Import wallet** — Word-by-word mnemonic entry with autocomplete
- **Shielded address** — Orchard Unified Address with QR code display
- **USB Serial Signer** — Sign transactions via HWP v3 protocol with on-device confirmation (recipient, amount, fee)
- **Shielded sighash verification** — On-device staged ZIP-244 verification: the companion sends transaction metadata and action data individually, the device hashes them incrementally and compares the computed sighash against the companion's before allowing any Orchard signature
- **Transparent input support** — On-device BLAKE2b computation of the ZIP-244 transparent txid digest (prevouts, sequences, outputs) from the wire data sent by the companion, matched against the transparent digest embedded in the transaction metadata
- **Transparent ECDSA signing** — On-device per-input sighash computation (ZIP-244 S.2) and secp256k1 ECDSA signing with RFC-6979 deterministic nonces, DER-encoded response; no private key ever leaves the device
- **Network discrimination** — Companion advertises its coin type in `FVK_REQ`; the device enforces that the session coin type, the transaction metadata coin type, and the recipient address prefix (`u` / `utest`) all agree before signing
- **Key export** — Full Viewing Key (ak, nk, rivk) for watch-only wallets
- **Mainnet/Testnet** — Switch between ZEC and TAZ networks
- **Encrypted storage** — Mnemonic encrypted on SD card with RC4 (K1/K2 scheme)
- **Hardware RNG** — Uses the STM32WB55 true random number generator for all cryptographic randomness

## Signing Protocol (HWP v3)

The signing flow implements the staged verification protocol defined by `zcash-hw-wallet-sdk`. Transparent messages are optional and only sent for transactions that actually spend transparent inputs; orchard-only transactions still follow the v2 subset unchanged.

1. **Handshake** — Device sends PING, companion replies PONG
2. **FVK export** — Companion sends `FVK_REQ(coin_type)` for wallet pairing; device returns `FVK_RSP(ak || nk || rivk)` or `HWP_ERR_NETWORK_MISMATCH` if the device network differs from the companion's
3. **Transaction metadata** — `TX_OUTPUT(0xFFFF, N, metadata)` (129 bytes: version, branch ID, lock time, expiry, orchard flags, value balance, anchor, transparent/sapling digests, coin type)
4. **Transparent digest verification** *(optional, only for transparent spends)*:
   - `TX_TRANSPARENT_INPUT(i, num_inputs, input_data)` × num_inputs — prevout_hash, index, sequence, value, script_pubkey
   - `TX_TRANSPARENT_OUTPUT(j, num_outputs, output_data)` × num_outputs — value, script_pubkey
   - `TX_TRANSPARENT_INPUT(num_inputs, num_inputs, expected_digest)` — sentinel; the device computes the ZIP-244 transparent digest incrementally and checks it against both the sentinel value and the digest in the transaction metadata
5. **Orchard actions** — `TX_OUTPUT(i, N, action_data)` × N (820 bytes each: cv_net, nullifier, rk, cmx, ephemeral_key, enc_ciphertext, out_ciphertext)
6. **Shielded sighash verification** — `TX_OUTPUT(N, N, sighash)` sentinel; the device compares the computed sighash with the companion's
7. **User confirmation** — Device displays recipient, amount, fee; user approves or cancels
8. **Orchard signing** — `SIGN_REQ` × (spends to authorize) → `orchard_signer_sign()` (enforces verification invariant) → `SIGN_RSP(sig || rk)`
9. **Transparent signing** *(optional)* — For each transparent input, `TRANSPARENT_SIGN_REQ(input_index, total_inputs, input_data)`:
   - Device computes the per-input sighash from its cached transparent state (ZIP-244 S.2: `BLAKE2b("ZTxIdTranspaHash", hash_type || prevouts || amounts || scripts || sequence || outputs || txin_sig)`)
   - Device signs the digest with secp256k1 ECDSA (RFC-6979 deterministic nonce, low-S normalized)
   - Response: `TRANSPARENT_SIGN_RSP(der_sig_len || der_sig || sighash_type || pubkey33)`

The `OrchardSignerCtx` state machine in libzcash-orchard-c guarantees at the library level that signatures cannot be produced without completing the relevant verification step: Orchard signatures require `VERIFIED` state, and `TRANSPARENT_SIGN_REQ` is rejected unless `transparent_verified` is set.

### Key derivation

Transparent inputs are spent from the standard Zcash BIP-32 path `m / 44' / coin_type' / 0' / 0 / 0` (133 for mainnet, 1 for testnet). The transparent spending key and compressed pubkey are derived once per signing session at sign-mode entry and cached in RAM alongside the Orchard keys; the BIP-39 seed is zeroed immediately after derivation and never persisted.

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
  application.fam              App manifest
  flipz.h / flipz.c            App entry point, scene dispatch
  flipz_coins.h / .c           Coin type definitions (ZEC/TAZ)
  helpers/
    flipz_file.*               Encrypted wallet storage (wallet.dat)
    flipz_string.*             Hex conversion, RC4 cipher
    flipz_serial.*             USB CDC serial communication
    flipz_rng.c                Hardware RNG bridge (STM32WB55 → libzcash)
    flipz_custom_event.h       Input event definitions
  scenes/
    flipz_scene_menu.c         Main menu
    flipz_scene_settings.c     Network, BIP-39 strength, passphrase
    flipz_scene_scene_1.c      Scene dispatcher for views
  views/
    flipz_scene_1.*            Address generation, key display, serial signer
  lib/
    libzcash-orchard-c/        Zcash crypto library (git submodule)
    qrcode/                    QR code generation (qrcodegen)
  .github/workflows/build.yml  CI: build the FAP on push / pull request
```

## Comparison with Other Zcash Hardware Wallets

| | **FlipZcash** | **`hhanh00/zcash-ledger`** | **Zondax `ledger-zcash`** | **Keystone 3 Pro × Zashi** |
|---|---|---|---|---|
| Device | Flipper Zero (STM32WB55) | Ledger Nano S+/X | Ledger Nano S+/X/Stax | Keystone 3 Pro (MH1903) |
| Pools supported | Orchard + transparent | Sapling + Orchard | Sapling + transparent | Orchard + transparent |
| License | MIT | Apache-2.0 | Apache-2.0 | MIT |
| Source language | C (plain C11) | C (BOLOS-bound) | C (BOLOS-bound) | Rust (vendored librustzcash) |
| Reusable as a library | **Yes** (`libzcash-orchard-c` is vendor-neutral, MIT, plain C) | No (BOLOS-coupled) | No (BOLOS-coupled) | No (Keystone-3-coupled) |
| Distribution | Sideload (Unleashed firmware FAP) | Sideload (Ledger sideload, not in Ledger Live) | Awaiting Ledger Live release | Shipped with Keystone 3 Pro firmware |
| On-device sighash verification | ✅ library-enforced invariant | Yes (firmware-side) | Yes (firmware-side) | Yes (firmware-side) |
| Wire protocol | HWP (binary, CRC-16/CCITT, 14 msg types) | APDU (Ledger BOLOS) | APDU (Ledger BOLOS) | QR codes (UR-encoded PCZT) |
| Companion | `zipher-cli` (Rust, open) | YWallet | (Sideload tool) | Zashi mobile (required) |
| Audit | ❌ | ❌ at original ZCG approval; ZecSec audit performed later | Audit funded inside grant | ❌ at grant approval; M2 of OneKey-style roadmap |
| Mainnet shielded broadcast | ✅ tx `1c9eb6ca…5466b` (2026-03-30) | ✅ | (Sapling only) | ✅ |

FlipZcash's distinguishing technical contribution is not the Flipper Zero
firmware itself but the underlying
[`libzcash-orchard-c`](https://github.com/wh00hw/libzcash-orchard-c) library:
the first portable, vendor-neutral, MIT-licensed plain-C implementation of
the Orchard primitives. The same library powers an ESP32-S2 reference port
([`zcash-hw-wallet-esp32`](https://github.com/wh00hw/zcash-hw-wallet-esp32))
without modification, demonstrating cross-MCU portability.

## Disclaimer

This software is a **proof-of-concept** born from an experimental exploration of Zcash Orchard on embedded hardware. It has **not been audited** by any security firm. The cryptographic primitives were implemented from scratch in C and, while tested against official test vectors, may contain subtle bugs.

**Use at your own risk.** 

## License

MIT — see [`LICENSE`](LICENSE).
