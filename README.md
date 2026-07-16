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

At rest, the mnemonic is PIN-sealed on the SD card (AES-256-CTR + HMAC-SHA256
AEAD, PIN-derived key); while the wallet is unlocked it is cached in RAM for
the session, and per signing session the Orchard + transparent keys are
re-derived and the BIP-39 seed zeroed immediately afterwards.

**No-blind-signing as a library invariant.** Five checkpoints, all enforced by the C library `lib/libzcash-ironwood-c/`, gate every signature:

1. **Sapling-component lockout** — `orchard_signer_feed_meta()` aborts with `SIGNER_ERR_SAPLING_NOT_EMPTY` unless `sapling_digest` equals the ZIP-244 empty-bundle constant. The Flipper-Zcash wallet is Orchard-only by design, so this is a structural fit.
2. **Per-action NoteCommitment recomputation** — `orchard_signer_feed_action_with_note()` recomputes `cmx = Extract_P(NoteCommit(g_d, pk_d, value, rho, psi))` from the unencrypted note plaintext (recipient, value, rseed) the companion declares, and rejects mismatches with `SIGNER_ERR_NOTE_COMMITMENT_MISMATCH` before any data is shown to the user. Closes recipient substitution.
3. **Per-action `enc_ciphertext` recomputation (memo binding)** — for memo-carrying payloads (HWP v5/v6), the device re-derives `esk` from `rseed + rho` (ZIP-212), re-encrypts the note plaintext with ChaCha20-Poly1305 on-chip, and constant-time-compares the result against the action's `enc_ciphertext` + `ephemeral_key` (`SIGNER_ERR_MEMO_MISMATCH`). The memo the user reviews on-screen is the one the device itself verified — a hostile companion cannot show one memo and commit another on chain.
4. **Per-output user confirmation** — `orchard_signer_verify()` refuses to advance to `SIGNER_VERIFIED` unless every captured action has been explicitly confirmed via `orchard_signer_confirm_action()`. The dispatcher drives a review screen for each output (recipient's Bech32m Unified Address + value, followed by the verified memo when present), requiring an OK press to confirm and Back/Cancel to abort.
5. **Miner-fee confirmation + ZIP-244 sighash recomputation** — the device computes the fee on-chip from `t_in − t_out + value_balance` (with overflow/negative detection) and presents it for explicit approval before `orchard_signer_verify()` recomputes the full shielded sighash (four-leaf v5, or five-leaf v6 with the Ironwood pool digest) and constant-time-matches against the companion's value (`SIGNER_ERR_FEE_NOT_CONFIRMED` / `SIGNER_ERR_SIGHASH_MISMATCH`).

`orchard_signer_sign()` refuses to produce a signature unless the state machine is in `VERIFIED`. A buggy or hostile firmware port cannot bypass any of the checks because they live in the C library, not in device-specific code. The Flipper firmware is responsible only for wiring the UI callbacks that satisfy invariants (3)–(5); it does not make signing-policy decisions.

## Acknowledgments

The BIP39 mnemonic implementation and the overall Flipper Zero app architecture (scene manager, view dispatcher, encrypted storage) are based on [FlipBIP](https://github.com/xtruan/FlipBIP) by xtruan, to which I am a contributor.

## Dependencies

FlipZcash relies on two companion libraries, both purpose-built for this project:

- **[libzcash-ironwood-c](https://github.com/wh00hw/libzcash-ironwood-c)** (git submodule, formerly `libzcash-orchard-c`) — Pure C implementation of Zcash cryptography: Pallas curve arithmetic, Sinsemilla hash, RedPallas signatures, ZIP-32 key derivation, FF1-AES-256, F4Jumble, BIP-39, BIP-32, secp256k1 + ECDSA (RFC 6979), ChaCha20-Poly1305 note-encryption recomputation, full ZIP-244 sighash computation (v5 four-leaf and v6/Ironwood five-leaf, shielded and transparent txid digests + per-input sig digest), the `OrchardSigner` state machine for on-device verification, the target-agnostic HWP dispatcher (`hwp_dispatcher.h`), and the AEAD + PIN-KDF + lockout primitives used for sealed storage. Portable across embedded targets.

- **[zcash-hw-wallet-sdk](https://github.com/wh00hw/zcash-hw-wallet-sdk)** — Rust SDK implementing the host side of the Hardware Wallet Protocol (HWP, feature tiers v2–v6), the binary framed serial protocol used for communication between the Flipper Zero and the companion broadcast app. Handles PCZT parsing, Orchard/Ironwood proof generation, memo recovery via the device OVK, staged on-device verification for shielded and transparent bundles, and signature collection (RedPallas + ECDSA).

## Features

- **Generate wallet** — BIP-39 mnemonic (12/18/24 words) with optional passphrase
- **Import wallet** — Word-by-word mnemonic entry with autocomplete
- **Shielded address** — Orchard Unified Address with QR code display
- **USB Serial Signer** — Sign transactions via the HWP protocol (feature tiers v2–v6, driven by the library's `hwp_dispatcher_run()`); each output's recipient (UA or t-address) and value is shown on the device and must be confirmed individually before signing
- **Shielded sighash verification** — On-device staged ZIP-244 verification: the companion sends transaction metadata and action data individually, the device hashes them incrementally (v5 four-leaf tree, or v6/Ironwood five-leaf with pool-tagged actions) and compares the computed sighash against the companion's before allowing any signature
- **Per-action NoteCommitment verification** — Device recomputes the Sinsemilla-based `cmx` for every action from the unencrypted note plaintext (recipient, value, rseed) the companion declares, and rejects recipient-substitution attempts with `HWP_ERR_NOTE_COMMITMENT_MISMATCH` before any output is displayed
- **Memo verification + review scene** — For memo-carrying payloads the device recomputes `enc_ciphertext` on-chip (ZIP-212 esk derivation + ChaCha20-Poly1305) and rejects memo substitution (`HWP_ERR_MEMO_MISMATCH`); the verified memo is then shown on a dedicated paginated review screen (`PAGE_SIGN_REVIEW_MEMO`) right after its output's recipient/value review
- **Per-output review scene** — `PAGE_SIGN_REVIEW_OUTPUT` displays the full Bech32m Unified Address (wrapped on the LCD) and value of every output before signing; OK confirms, Back cancels. The libzcash signer state machine refuses to sign without an explicit confirm for every output
- **Miner-fee confirmation** — The fee is computed on-chip (`t_in − t_out + value_balance`, overflow-checked) and presented for explicit approval through the review flow; a companion that inflates `value_balance` cannot silently overspend
- **Sapling-component lockout** — Device enforces `sapling_digest` equal to the ZIP-244 empty-bundle constant; PCZTs containing Sapling spends or outputs are rejected before any orchard data is hashed
- **NU6.3 / Ironwood ready** — v6 transactions (pool-tagged actions, 170-byte TxMeta, sealed-Orchard flag policy, ZIP-2005 V3 notes) are handled transparently by the library dispatcher; the firmware is pool-agnostic
- **Transparent input support** — On-device BLAKE2b computation of the ZIP-244 transparent txid digest (prevouts, sequences, outputs) from the wire data sent by the companion, matched against the transparent digest embedded in the transaction metadata
- **Transparent ECDSA signing** — On-device per-input sighash computation (ZIP-244 S.2) and secp256k1 ECDSA signing with RFC-6979 deterministic nonces, DER-encoded response; no private key ever leaves the device
- **Network discrimination** — Companion advertises its coin type in `FVK_REQ`; the device enforces that the session coin type, the transaction metadata coin type, and the recipient address prefix all agree before signing
- **Key export** — Full Viewing Key (ak, nk, rivk) for watch-only wallets
- **Mainnet/Testnet** — Switch between ZEC and TAZ networks
- **PIN-sealed storage + lockout** — Mnemonic sealed on SD card with AES-256-CTR + HMAC-SHA256 AEAD under a PIN-derived key (PBKDF2, 50,000 iterations); 10 failed PIN attempts trigger a lockout with wallet wipe. Change-PIN and Wipe-wallet flows included. (Legacy RC4 `wallet.dat` files are still readable once, for migration only.)
- **Hardware RNG** — Uses the STM32WB55 true random number generator for all cryptographic randomness

## Signing Protocol (HWP)

The device side of the protocol is not implemented in the firmware: FlipZcash wires ~7 I/O + UI callbacks into the library's target-agnostic dispatcher (`hwp_dispatcher_run()` from `lib/libzcash-ironwood-c/`) and gets the entire state machine — frame parsing, message dispatch, keepalive, per-output review orchestration, fee review, recipient binding — for free. The same dispatcher code runs on the virtual-device test fixture and any future port. Transparent messages are optional and only sent for transactions that actually spend transparent inputs.

The session as driven by the dispatcher:

1. **Handshake** — Device sends PING, companion replies PONG
2. **FVK export** — Companion sends `FVK_REQ(coin_type)` for wallet pairing; device returns `FVK_RSP(ak || nk || rivk)` or `HWP_ERR_NETWORK_MISMATCH` if the device network differs from the companion's
3. **Transaction metadata** — `TX_OUTPUT(0xFFFF, N, metadata)`: 129 bytes for v5 sessions (version, branch ID, lock time, expiry, orchard flags, value balance, anchor, transparent/sapling digests, coin type) or 170 bytes for v6/Ironwood sessions (adds `ironwood_flags || ironwood_value_balance || ironwood_anchor`); the tier is discriminated by payload size
4. **Transparent digest verification** *(optional, only for transparent spends)*:
   - `TX_TRANSPARENT_INPUT(i, num_inputs, input_data)` × num_inputs — prevout_hash, index, sequence, value, script_pubkey
   - `TX_TRANSPARENT_OUTPUT(j, num_outputs, output_data)` × num_outputs — value, script_pubkey (captured for review, rendered as base58check t-addresses)
   - `TX_TRANSPARENT_INPUT(num_inputs, num_inputs, expected_digest)` — sentinel; the device computes the ZIP-244 transparent digest incrementally and checks it against both the sentinel value and the digest in the transaction metadata
5. **Shielded actions** — `TX_OUTPUT(i, N, action_data)` × N. Payload tiers: 903 bytes (v4/v5 cmx-only: 820-byte ZIP-244 action + `recipient[43] || value[8 LE] || rseed[32]`), 1415 bytes (v5 + `memo[512]`), or the v6 pool-tagged forms (1416/904 bytes, leading pool byte `0x00` sealed Orchard / `0x01` Ironwood). For each action the device recomputes the Sinsemilla note commitment from the trailing plaintext — and, for memo-carrying payloads, the full `enc_ciphertext` + `epk` via ZIP-212 esk derivation + ChaCha20-Poly1305 — and constant-time-compares against the encrypted action fields; mismatches abort with `HWP_ERR_NOTE_COMMITMENT_MISMATCH` / `HWP_ERR_MEMO_MISMATCH` before any user-visible step.
6. **Per-output review** — Before the sentinel sighash is verified, the dispatcher iterates the captured outputs (transparent t-addresses first, then shielded recipients as Bech32m UAs) and invokes the firmware's review callbacks: `PAGE_SIGN_REVIEW_OUTPUT` shows recipient + value, `PAGE_SIGN_REVIEW_MEMO` shows the device-verified memo (paginated, skipped when empty). OK (or Right) confirms, Back (or Left) cancels; cancellation aborts the session with `HWP_ERR_USER_CANCELLED`. Each confirm calls `orchard_signer_confirm_action(idx)`. The on-chip-computed miner fee is then presented for approval (`orchard_signer_confirm_fee()`).
7. **Shielded sighash verification** — `TX_OUTPUT(N, N, sighash)` sentinel; the device verifies all per-action confirmations plus the fee confirmation are recorded, compares the computed sighash with the companion's, and transitions to `SIGNER_VERIFIED`
8. **Orchard/Ironwood signing** — `SIGN_REQ` × (spends to authorize) → `orchard_signer_sign()` (enforces verification invariant) → `SIGN_RSP(sig || rk)`
9. **Transparent signing** *(optional)* — For each transparent input, `TRANSPARENT_SIGN_REQ(input_index, total_inputs, input_data)`:
   - Device computes the per-input sighash from its cached transparent state (ZIP-244 S.2: `BLAKE2b("ZTxIdTranspaHash", hash_type || prevouts || amounts || scripts || sequence || outputs || txin_sig)`)
   - Device signs the digest with secp256k1 ECDSA (RFC-6979 deterministic nonce, low-S normalized)
   - Response: `TRANSPARENT_SIGN_RSP(der_sig_len || der_sig || sighash_type || pubkey33)`

The `OrchardSignerCtx` state machine in libzcash-ironwood-c guarantees at the library level that signatures cannot be produced without completing every verification step:

- `feed_meta()` rejects `sapling_digest ≠ empty-bundle constant` (and, on v6, enforces the header constants + sealed-Orchard flag policy)
- `feed_action_with_note[_and_memo]()` rejects `cmx ≠ Sinsemilla-NoteCommit(declared note plaintext)` and `enc_ciphertext ≠ ChaCha20-Poly1305(declared memo)`
- `verify()` requires every action to have been explicitly confirmed via `confirm_action()` and the fee via `confirm_fee()`
- `verify()` recomputes the full ZIP-244 sighash on-device and refuses on mismatch
- `sign()` refuses unless `state == VERIFIED`
- `TRANSPARENT_SIGN_REQ` is rejected unless `transparent_verified` is set

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
  application.fam              App manifest (RAM-tuning cdefines: MAX_ACTIONS=8,
                               MAX_MEMOS=4, HWP_MAX_PAYLOAD=1536)
  flipz.h / flipz.c            App entry point, scene dispatch, mnemonic cache
  flipz_coins.h / .c           Coin type definitions (ZEC/TAZ)
  helpers/
    flipz_secure.*             PIN-sealed wallet storage (AEAD + PBKDF2 + lockout)
    flipz_file.*               wallet.dat: legacy RC4 mnemonic section (migration
                               only) + derived-key/address cache

    flipz_string.*             Hex conversion, RC4 cipher (legacy)
    flipz_serial.*             USB CDC serial communication
    flipz_rng.c                Hardware RNG bridge (STM32WB55 → libzcash)
    flipz_custom_event.h       Input event definitions
  scenes/
    flipz_scene_menu.c         Main menu
    flipz_scene_pin.c          PIN unlock / provision / change (async worker)
    flipz_scene_settings.c     Network, BIP-39 strength, passphrase
    flipz_scene_scene_1.c      Scene dispatcher for views
  views/
    flipz_scene_1.*            Address generation, key display, HWP dispatcher
                               glue (review/memo/confirm callbacks), QR render
    flipz_pin_input.*          PIN entry view
    flipz_progress.*           Progress bar view (key derivation, PIN KDF)
  lib/
    libzcash-ironwood-c/       Zcash crypto library (git submodule)
    qrcode/                    QR code generation (qrcodegen)
  .github/workflows/build.yml  CI: build the FAP on push / pull request
```

## Comparison with Other Zcash Hardware Wallets

| | **FlipZcash** | **`hhanh00/zcash-ledger`** | **Zondax `ledger-zcash`** | **Keystone 3 Pro × Zashi** |
|---|---|---|---|---|
| Device | Flipper Zero (STM32WB55) | Ledger Nano S+/X | Ledger Nano S+/X/Stax | Keystone 3 Pro (MH1903) |
| Pools supported | Orchard + Ironwood (NU6.3) + transparent | Sapling + Orchard | Sapling + transparent | Orchard + transparent |
| License | MIT | Apache-2.0 | Apache-2.0 | MIT |
| Source language | C (plain C11) | C (BOLOS-bound) | C (BOLOS-bound) | Rust (vendored librustzcash) |
| Reusable as a library | **Yes** (`libzcash-ironwood-c` is vendor-neutral, MIT, plain C) | No (BOLOS-coupled) | No (BOLOS-coupled) | No (Keystone-3-coupled) |
| Distribution | Sideload (Unleashed firmware FAP) | Sideload (Ledger sideload, not in Ledger Live) | Awaiting Ledger Live release | Shipped with Keystone 3 Pro firmware |
| On-device sighash verification | ✅ library-enforced invariant | Yes (firmware-side) | Yes (firmware-side) | Yes (firmware-side) |
| Per-action NoteCommitment recomputation | ✅ Sinsemilla NoteCommit on-device, KAT vs librustzcash | Yes (firmware-side) | Yes (firmware-side) | Yes (firmware-side) |
| Per-output user confirmation as library invariant | ✅ `verify()` refuses without `confirm_action()` per output; UI cannot bypass | Firmware convention | Firmware convention | Firmware convention |
| Wire protocol | HWP (binary, CRC-16/CCITT, 18 msg types) | APDU (Ledger BOLOS) | APDU (Ledger BOLOS) | QR codes (UR-encoded PCZT) |
| Companion | `zipher-cli` (Rust, open) | YWallet | (Sideload tool) | Zashi mobile (required) |
| Audit | ❌ | ❌ at original ZCG approval; ZecSec audit performed later | Audit funded inside grant | ❌ at grant approval; M2 of OneKey-style roadmap |
| Mainnet shielded broadcast | ✅ tx `1c9eb6ca…5466b` (2026-03-30) | ✅ | (Sapling only) | ✅ |

FlipZcash's distinguishing technical contribution is not the Flipper Zero
firmware itself but the underlying
[`libzcash-ironwood-c`](https://github.com/wh00hw/libzcash-ironwood-c) library:
the first portable, vendor-neutral, MIT-licensed plain-C implementation of
the Orchard (and now Ironwood) primitives. The same library powers an ESP32-S2
reference port
([`zcash-hw-wallet-esp32`](https://github.com/wh00hw/zcash-hw-wallet-esp32))
without modification, demonstrating cross-MCU portability.

## Disclaimer

This software is a **proof-of-concept** born from an experimental exploration of Zcash Orchard on embedded hardware. It has **not been audited** by any security firm. The cryptographic primitives were implemented from scratch in C and, while tested against official test vectors, may contain subtle bugs.

**Use at your own risk.** 

## License

MIT — see [`LICENSE`](LICENSE).
