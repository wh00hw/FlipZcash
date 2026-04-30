# FlipZcash — Implementation

Technical documentation of the FlipZcash hardware-wallet stack as it ships
today: cryptographic primitives, key-derivation pipeline, on-device signing
state machine, wire protocol, performance, security model, and standards
conformance. This is a description of the final implementation; the
companion [`README.md`](README.md) gives the user-facing overview.

---

## 1. Repository Layout

### Cryptographic library — `lib/libzcash-orchard-c/` (git submodule)

A standalone, MIT-licensed, zero-dependency C11 library
([github.com/wh00hw/libzcash-orchard-c](https://github.com/wh00hw/libzcash-orchard-c))
consumed unmodified by FlipZcash and by the ESP32-S2 reference port
(`zcash-hw-wallet-esp32`). Files linked into the FlipZcash `.fap` via
`application.fam`:

| File | Role |
|------|------|
| `src/pallas.c` | Pallas field & curve arithmetic, constant-time Montgomery ladder, Sinsemilla hash with pluggable lookup-callback |
| `src/orchard.c` | ZIP-32 Orchard derivation, FF1-AES-256 diversifier, F4Jumble, ZIP-316 Unified Address encoding |
| `src/redpallas.c` | RedPallas spend-authorization signing (RFC-6979-style nonce derived from BLAKE2b-512) |
| `src/zip244.c` | Incremental ZIP-244 shielded sighash + transparent digest computation |
| `src/orchard_signer.c` | Library-enforced state machine: signing refuses to run unless the sighash has been verified on-device |
| `src/hwp.c` | Hardware Wallet Protocol parser/encoder (CRC-16/CCITT, frame state machine) |
| `src/bip32.c`, `src/bip39.c`, `src/bip39_english.c` | HD-key derivation, BIP-39 mnemonic generation/validation |
| `src/secp256k1.c` | secp256k1 ECDSA (RFC-6979 deterministic nonce, low-S normalized, DER) for transparent inputs |
| `src/blake2b.c`, `src/sha2.c`, `src/hmac.c`, `src/pbkdf2.c`, `src/aes/*` | Vendored primitives (trezor-crypto / Gladman AES) |
| `src/segwit_addr.c` | Bech32m encoding (extended length limits for Unified Address) |

### FlipZcash application — repository root

Top-level FAP-specific code, ~3,140 hand-written LOC of C, that drives the
library above with Flipper-specific UI, storage, USB, and RNG glue:

| File | Role |
|------|------|
| `flipz.c`, `flipz.h` | App entry (`flipz_app`), allocation, scene/view dispatch, BIP-39 word-by-word import flow with autocomplete |
| `flipz_coins.c`, `flipz_coins.h` | Coin enum (`CoinTypeZECOrchard = 133`, `CoinTypeZECOrchardTest = 1`) |
| `application.fam` | App manifest declaring `libzcash-orchard-c` and `qrcode` as private libs |
| `helpers/flipz_file.{c,h}` | `wallet.dat` storage (magic `FZ01`, RC4 K1/K2 layout, mainnet/testnet keys, backup) |
| `helpers/flipz_string.{c,h}` | Hex conversion + `flipz_cipher` (RC4 wrapper) |
| `helpers/flipz_serial.{c,h}` | USB-CDC transport: `flipz_serial_init`, `_send_raw`, `_drain` |
| `helpers/flipz_rng.c` | STM32WB55 hardware-RNG bridge into libzcash's `random_buffer` |
| `helpers/flipz_custom_event.h` | Input event enum |
| `scenes/flipz_scene_menu.c` | Main submenu (Address / USB Serial Signer / Keys / Mnemonic / Regenerate / Import / Settings) |
| `scenes/flipz_scene_settings.c` | Network toggle, BIP-39 strength (128/192/256), passphrase toggle |
| `scenes/flipz_scene_scene_1.c`, `flipz_scene.{c,h}`, `flipz_scene_config.h` | Scene routing |
| `views/flipz_scene_1.c` | Workhorse: key/address derivation worker thread, HWP message dispatcher (sign worker), QR + address rendering, sighash UI |

The `lib/qrcode/` directory ships Project Nayuki's `qrcodegen` for on-screen
QR rendering of the Unified Address.

---

## 2. Hardware Target

| Resource | Value | Notes |
|----------|-------|-------|
| MCU | STM32WB55 | Single-core ARM Cortex-M4 |
| Clock | 64 MHz | No FPU |
| RAM | 256 KiB total | ~100 KiB usable after OS + binary; 4 KiB app stack, 8 KiB worker-thread stack |
| Storage | SD card (FAT32) | Slow random access, fast sequential — used for wallet, LUT, and address cache |
| Crypto bridge | Hardware RNG | `furi_hal_random_*` → `helpers/flipz_rng.c` → `random_buffer` |
| Secure element | None | All primitives run in main MCU memory |

---

## 3. Architecture — Delegated Signing

The signing work is split between FlipZcash (the device) and a companion
application (the Rust SDK [`zcash-hw-wallet-sdk`](https://github.com/wh00hw/zcash-hw-wallet-sdk),
typically driven by `zipher-cli`):

```
┌──────────────────────┐                    ┌──────────────────────────┐
│     Flipper Zero     │                    │     Companion App        │
│                      │                    │                          │
│  Holds:              │   FVK export       │   Holds: FVK             │
│  - ask  (NEVER       │ ─────────────────> │     (ak, nk, rivk)       │
│         leaves)      │                    │   (watch-only)           │
│  - nk, rivk, fvk     │                    │                          │
│  - transparent SK    │   HWP frames       │   Does:                  │
│    (session-cached)  │ <───────────────── │   - blockchain sync      │
│                      │                    │   - PCZT construction    │
│  Does:               │   sighash + alpha  │   - Halo2 proof gen      │
│  - on-device ZIP-244 │ <───────────────── │   - witness assembly     │
│    sighash verify    │                    │   - signature injection  │
│  - user confirmation │   sig + rk         │   - broadcast            │
│  - RedPallas signing │ ─────────────────> │                          │
│  - secp256k1 ECDSA   │                    │                          │
│    (transparent)     │                    │                          │
└──────────────────────┘                    └──────────────────────────┘
```

The spending key `ask` never leaves the device. The companion only ever
holds the Full Viewing Key, which lets it watch the chain and assemble
transactions but cannot authorize a spend.

In Orchard, only the RedPallas spend-authorization signature requires `ask`.
Everything else (Halo2 proof, nullifier derivation, value commitment, note
encryption, binding signature) can be computed from the FVK.

---

## 4. Wire Protocol — HWP

The companion ↔ device link is a binary framed protocol over USB-CDC
serial. The byte layout:

```
[MAGIC:0xFB][VER:0x02][SEQ:1][TYPE:1][LEN_LE:2][PAYLOAD][CRC16_LE:2]
```

CRC-16/CCITT (poly `0x1021`, init `0xFFFF`) over the entire header + payload.

### Message types

| Type | Direction | Payload | Purpose |
|------|-----------|---------|---------|
| `PING (0x01)` | F→C | empty | Connect / session reset |
| `PONG (0x02)` | C→F | empty | Acknowledgement |
| `FVK_REQ (0x03)` | C→F | `coin_type[4]` | Pair: companion advertises its network |
| `FVK_RSP (0x04)` | F→C | `ak[32] || nk[32] || rivk[32]` | Export Full Viewing Key |
| `SIGN_REQ (0x05)` | C→F | `sighash[32] || alpha[32] || amount[8] || fee[8] || rlen[1] || recipient[N]` | Request RedPallas signature for an action |
| `SIGN_RSP (0x06)` | F→C | `sig[64] || rk[32]` | RedPallas signature + randomized key |
| `ERROR (0x07)` | either | `code[1] || message[N]` | Explicit error frame |
| `TX_OUTPUT (0x08)` | C→F | `idx_le[2] || total_le[2] || data[N]` | Stream tx metadata (idx 0xFFFF) / actions / sighash sentinel |
| `TX_OUTPUT_ACK (0x09)` | F→C | `idx_le[2]` | Per-frame acknowledgement |
| `ABORT (0x0A)` | C→F | empty | Cancel session, reset state |
| `TX_TRANSPARENT_INPUT (0x0B)` | C→F | `idx_le[2] || total_le[2] || data[N]` | Stream transparent inputs / digest sentinel |
| `TX_TRANSPARENT_OUTPUT (0x0C)` | C→F | `idx_le[2] || total_le[2] || data[N]` | Stream transparent outputs |
| `TRANSPARENT_SIGN_REQ (0x0D)` | C→F | `idx_le[2] || total_le[2] || data[N]` | Per-input ECDSA signing request |
| `TRANSPARENT_SIGN_RSP (0x0E)` | F→C | `der_len[1] || der_sig[N] || sighash_type[1] || pubkey33[33]` | DER-encoded ECDSA signature + compressed pubkey |

### Error codes

| Code | Meaning |
|------|---------|
| `0x05` | Network mismatch (session coin type ≠ tx metadata coin type ≠ recipient prefix) |
| `0x0A` | Session-level abort |
| `0x0B` | Transparent digest mismatch (recomputed digest ≠ companion-supplied digest) |
| Other | Sighash mismatch / state-machine violation / parser error |

The version byte on the wire is `0x02`; the device accepts both `0x01`
(legacy) and `0x02` inbound and always emits `0x02` outbound.

---

## 5. On-Device ZIP-244 Sighash Verification

The signing path is gated by a state machine implemented inside the
cryptographic library (`OrchardSignerCtx` in
`lib/libzcash-orchard-c/src/orchard_signer.c`). Any caller — FlipZcash,
the ESP32-S2 reference port, or a future third-party wallet — gets the
verification check for free and cannot bypass it:

```
                           ┌────────────────────────┐
                           │       SIGNER_INIT      │
                           └────────────┬───────────┘
                                        │ feed_meta()
                                        ▼
                           ┌────────────────────────┐
                           │   SIGNER_HAS_META      │
                           └────────────┬───────────┘
                                        │ feed_action() × N
                                        ▼
                           ┌────────────────────────┐
                           │  SIGNER_HAS_ACTIONS    │
                           └────────────┬───────────┘
                                        │ verify(expected_sighash)
                                        │   compares device sighash
                                        │   to expected, ct-equal
                                        ▼
                           ┌────────────────────────┐
                           │   SIGNER_VERIFIED      │ ──── sign(): only here
                           └────────────────────────┘
```

`orchard_signer_sign()` rejects the call unless the state has reached
`SIGNER_VERIFIED`. A buggy or hostile firmware cannot bypass the check
because the rejection is in the C library, not in device-specific code.

Transparent signing follows the same pattern with a separate
`transparent_verified` flag set after the device recomputes the
ZIP-244 transparent txid digest from the streamed inputs/outputs and
matches it against both the sentinel digest and the digest in the
transaction metadata.

---

## 6. Signing Flow (HWP)

```
1. Handshake
   F → C: PING
   C → F: PONG

2. FVK export
   C → F: FVK_REQ(coin_type)
   F → C: FVK_RSP(ak || nk || rivk)
            or HWP_ERR_NETWORK_MISMATCH if network differs

3. Transaction metadata
   C → F: TX_OUTPUT(idx=0xFFFF, total=N, metadata[129])
            (version, branch ID, lock time, expiry,
             orchard flags, value balance, anchor,
             transparent + sapling digests, coin type)
   F → C: TX_OUTPUT_ACK(0xFFFF)

4. Transparent digest verification (only for transparent spends)
   For each transparent input i in 0..num_inputs:
     C → F: TX_TRANSPARENT_INPUT(i, num_inputs, input_data)
   Sentinel:
     C → F: TX_TRANSPARENT_INPUT(num_inputs, num_inputs, expected_digest)
   For each transparent output j in 0..num_outputs:
     C → F: TX_TRANSPARENT_OUTPUT(j, num_outputs, output_data)
   Device cross-checks computed digest against sentinel and metadata.

5. Orchard actions
   For each action i in 0..N-1:
     C → F: TX_OUTPUT(i, N, action_data[820])
              (cv_net, nullifier, rk, cmx, ephemeral_key,
               enc_ciphertext, out_ciphertext)
     F → C: TX_OUTPUT_ACK(i)

6. Shielded sighash sentinel
   C → F: TX_OUTPUT(N, N, expected_sighash[32])
   Device hashes actions incrementally (BLAKE2b-256 × 3) and compares
   against the sentinel; on match → SIGNER_VERIFIED.

7. User confirmation on screen
   Device displays recipient + amount + fee, awaits OK / Cancel.

8. Orchard signing (per spend action)
   C → F: SIGN_REQ(sighash, alpha, amount, fee, recipient)
   F → C: SIGN_RSP(sig || rk)
   The library refuses unless state = SIGNER_VERIFIED.

9. Transparent signing (per transparent input, optional)
   C → F: TRANSPARENT_SIGN_REQ(i, num_inputs, input_data)
   Device computes per-input sighash (ZIP-244 §S.2) from cached
   transparent state, signs with secp256k1 ECDSA (RFC-6979 nonce,
   low-S), DER-encodes, and replies:
   F → C: TRANSPARENT_SIGN_RSP(der_len || der_sig || sighash_type || pubkey33)
```

---

## 7. Key Derivation Pipeline

```
BIP-39 mnemonic (12/18/24 words)
         │
         ▼  PBKDF2-HMAC-SHA512 (2048 iter, optional passphrase)
    Seed (64 bytes)
         │
         ▼  BLAKE2b-512(personal="ZcashIP32Orchard", input=seed)
    sk_m (32) || cc_m (32)
         │
         ▼  3 hardened levels
    m_Orchard / 32' / coin_type' / 0'
         │
    sk_account (32 bytes)
         │
         ├── PRF^expand(sk, 0x06) → ToScalar → ask  (spend authorization)
         ├── PRF^expand(sk, 0x07) → ToBase   → nk   (nullifier deriving)
         └── PRF^expand(sk, 0x08) → ToScalar → rivk (commitment randomness)
                              │
                              ▼
    ak  = [ask] · G_spend
    IVK = SinsemillaShortCommit("z.cash:Orchard-CommitIvk",
                                nk[255 bit] || ak.x[255 bit], rivk)
    dk  = PRF^expand(rivk, [0x82] || ak_compressed || nk)[:32]
    d   = FF1-AES-256(dk, [0]·11)
    g_d = DiversifyHash(d) = hash_to_curve("z.cash:Orchard-gd", d)
    pk_d = [ivk] · g_d
                              │
                              ▼
    UA = Bech32m(hrp,
                 F4Jumble([0x03][43] || d[11] || pk_d[32] || hrp_padded[16]))
```

Transparent inputs follow the standard Zcash BIP-44 path
`m / 44' / coin_type' / 0' / 0 / 0` (133 mainnet, 1 testnet). The
transparent spending key and compressed pubkey are derived once per
signing session and cached in RAM alongside the Orchard keys; the
BIP-39 seed is zeroed immediately after derivation and never persisted.

---

## 8. Sinsemilla Lookup Table

Sinsemilla processes a 510-bit message (for `CommitIvk`) in 51 ten-bit
chunks; each chunk calls `GroupHash` (= `hash_to_curve`) plus a point
addition and doubling. On a 64 MHz Cortex-M4 the on-the-fly path costs
~12 minutes per `CommitIvk`. A precomputed lookup table eliminates the
51 `hash_to_curve` calls.

### Format

`sinsemilla_s.bin`: **65,536 bytes** = 1024 × 64 bytes. Each 64-byte
record is a Pallas curve point (`x || y`, little-endian, 32 bytes each)
representing
`S_i = hash_to_curve("z.cash:SinsemillaS")(i.to_le_bytes())`
for `i ∈ 0..1024`.

### Loading

The library exposes a pluggable lookup callback,
`pallas_set_sinsemilla_lookup(fn, ctx)` in
`lib/libzcash-orchard-c/src/pallas.c`. FlipZcash registers a callback
that seeks into the SD-card file and returns the 64-byte record for the
requested index:

- Path: `apps_data/flipz/sinsemilla_s.bin`
- Registration: `views/flipz_scene_1.c::sinsemilla_lookup_init`

If the file is absent the library falls back transparently to on-the-fly
`hash_to_curve` (~15 minutes for the first generation). If present, the
LUT path completes the same derivation in ~90 seconds.

### Verifiability

Each LUT entry is independently reproducible: any caller can recompute
`hash_to_curve("z.cash:SinsemillaS", i)` and check the bytes match. No
attestation or signature on the LUT is required; correctness is
established by the 49 known-answer vectors in
`lib/libzcash-orchard-c/tests/test_vectors.c`.

The ESP32-S2 reference port (`zcash-hw-wallet-esp32`) embeds the same
LUT into firmware via `EMBED_FILES`; FlipZcash chose SD-card loading to
keep the FAP small.

---

## 9. Cryptographic Primitives — Implementation Notes

The Orchard primitives are implemented from scratch in plain C against
the Zcash Protocol Specification v2024.5.1 (NU6.1).

### Pallas field arithmetic

The Pallas prime `p ≈ 2^254` is incompatible with the Barrett-reduction
optimization used by trezor-crypto's `bn_mod` / `bn_fast_mod`, which
assume primes near 2^256. The library uses a **bit-by-bit Horner
reduction** that is universal — it works for any prime. Cost:
O(522) shift+compare+subtract operations per multiplication.

```c
void fp_mul(bignum256* r, const bignum256* a, const bignum256* b) {
    uint32_t res[18];                  // 18 limbs = 522 bits
    bn_multiply_long(a, b, res);
    for (int limb = 17; limb >= 0; limb--) {
        for (int bit = 28; bit >= 0; bit--) {
            bn_lshift(r);
            if (res[limb] & (1u << bit)) r->val[0] |= 1;
            if (!bn_is_less(r, &s_p)) bn_subtract(r, &s_p, &tmp);
        }
    }
}
```

Modular inversion uses Stein's binary extended GCD (~400 iterations of
shift/subtract) rather than Fermat's `a^(p-2) mod p` (~256 modular
multiplications).

### Pallas scalar field

The same bit-by-bit Horner technique is applied to the scalar field
`q ≈ 2^254`. All scalar arithmetic in `redpallas.c` uses the
prime-agnostic `fq_full_reduce`, `fq_mul`, `fq_add`, `fq_from_wide`
helpers; `bn_multiply` is not used for any reduction step.

### Modular square root

Curve-point decompression needs `sqrt(x³ + 5) mod p`. Tonelli-Shanks with
`p − 1 = 2^32 · T` (S = 32, unusually high for Pallas) and a precomputed
quadratic non-residue generator `z = 5^T mod p`.

### Hash-to-curve (RFC 9380 + isogeny)

Three-stage pipeline as required by the RFC:

1. `expand_message_xmd` with **BLAKE2b-512** (not SHA-256) and the Zcash
   DST `domain + "-pallas_XMD:BLAKE2b_SSWU_RO_" + len_byte`. Outputs 128
   bytes via XOR chain.
2. `map_to_curve_swu` on iso-Pallas (`y² = x³ + Ax + B`, A and B fixed).
3. Degree-3 isogeny `iso_map` from iso-Pallas back to Pallas, using 13
   precomputed coefficients (32-byte big-endian field elements).

### RedPallas signing

Deterministic spend-authorization signing. Nonce derivation is
RFC-6979-style from `BLAKE2b-512(rsk || sighash)`; the wide reduction
maps the 64-byte hash into the scalar field via the Horner technique.
Signature equation: `S = nonce + challenge · rsk`, with all arithmetic
in the scalar field.

### FF1-AES-256 format-preserving encryption

Orchard diversifier derivation per NIST SP 800-38G with `radix = 2`,
`n = 88` bits. 10-round Feistel network on 88 bits; the
BinaryNumeralString mapping is bit-level (numeral `i` at bit `i%8` of
byte `i/8`, with the NUM_2 reading numeral 0 as MSB).

### F4Jumble (ZIP-316)

4-round Feistel using two BLAKE2b functions:
- `H_i(u)`: single-block BLAKE2b with personalization `"UA_F4Jumble_H" || i`
- `G_i(u)`: counter-mode BLAKE2b for variable output length

Round structure:
```
x = B ^ G(0, A)
y = A ^ H(0, x)
d = x ^ G(1, y)
c = y ^ H(1, d)
output = c || d
```

### Bech32m

Direct call to `bech32_encode()` with `BECH32_ENCODING_BECH32M`
(constant `0x2bc830a3`); the SegWit length-limit check in
`segwit_addr_encode` is bypassed because Unified Addresses are longer
than SegWit allows. The 8-to-5-bit conversion is implemented manually.

### BLAKE2b extension

trezor-crypto's BLAKE2b only exposed `Init`, `InitKey`, `Update`,
`Final`. Two helpers were added for ZIP-32 / Orchard:

```c
int blake2b_InitPersonal(blake2b_state* S, size_t outlen,
                         const void* personal, size_t personal_len);
int blake2b_InitKeyPersonal(blake2b_state* S, size_t outlen,
                            const void* key, size_t keylen,
                            const void* personal, size_t personal_len);
```

Both set `P->personal` in the BLAKE2b parameter block before state init.

### secp256k1 ECDSA

For transparent inputs. RFC-6979 deterministic nonce derivation (no RNG
in the signing path), low-S normalization to match Zcash policy,
DER encoding via `secp256k1_sig_to_der`. Verification path is not used
on-device — the companion verifies signatures before injecting them
into the PCZT.

---

## 10. Memory and Watchdog Discipline

### 4 KiB stack budget

The application stack is 4 KiB (8 KiB for the worker thread).

- **`static` locals in hot functions.** `fp_mul`, `fp_inv`, `fp_sqrt`
  and the point routines use file-scope `static` locals to keep
  `bignum256` work areas in BSS rather than on stack:
  ```c
  void fp_mul(bignum256* r, const bignum256* a, const bignum256* b) {
      static uint32_t res[18];
      static bignum256 tmp;
      ...
  }
  ```
- **Heap for large buffers** — address buffer (256 B), display strings,
  worker context.
- **Buffer reuse** wherever data lifetimes allow.
- **Systematic `memzero`.** All buffers holding `sk`, `ask`, `nk`,
  `rivk`, `seed`, mnemonic are zeroed immediately after use.

### Watchdog yielding

The Flipper has a hardware watchdog that resets the device if the main
thread fails to yield. The library exposes a yield hook called from the
inner arithmetic loops; the FlipZcash binding calls `furi_delay_tick(1)`
every 5 hot operations:

```c
static uint32_t s_yield_counter = 0;
static inline void pallas_yield(void) {
    if (++s_yield_counter >= 5) {
        s_yield_counter = 0;
        furi_delay_tick(1);
    }
}
```

The same hook is a no-op on platforms without a watchdog (e.g. ESP32-S2).

---

## 11. Performance

All measurements on Flipper Zero (STM32WB55 @ 64 MHz):

| Operation | Time | Notes |
|-----------|-----:|-------|
| BIP-39 seed generation | < 1 s | PBKDF2 2048 iterations |
| ZIP-32 derivation (master + 3 child) | < 1 s | 4× BLAKE2b-512 |
| `ask`, `nk`, `rivk` derivation | < 1 s | 3× PRF^expand + reduce |
| `[ask] · G_spend` | ~20 s | 256 doubles + ~128 adds |
| Sinsemilla IVK without LUT | ~12 min | 51× `GroupHash` + point ops |
| Sinsemilla IVK with `sinsemilla_s.bin` | ~10 s | LUT replaces all `GroupHash` calls |
| FF1-AES-256 diversifier | < 1 s | 10 rounds AES |
| `DiversifyHash` | ~30 s | 1× `hash_to_curve` |
| `[ivk] · g_d` | ~3-5 min | 256 doubles + ~128 adds |
| F4Jumble + Bech32m | < 1 s | 4× BLAKE2b + encoding |
| ZIP-244 sighash (per action) | < 100 ms | BLAKE2b-256 incremental |
| RedPallas spend-auth signature | ~5-6 s | 1 scalar mul + nonce derivation |
| secp256k1 ECDSA (transparent) | ~1 s | 1 scalar mul + RFC-6979 nonce |
| **First UA generation, no LUT** | **~15-18 min** | one-time |
| **First UA generation, with LUT** | **~1.5 min** | one-time |
| **Subsequent launches** | **instant** | UA loaded from `wallet.dat` |
| **End-to-end mainnet broadcast** | **~20 s** | excluding companion's Halo2 proof (~2 min on desktop) |

---

## 12. Standards Conformance

| Standard | Status | Notes |
|----------|--------|-------|
| BIP-32 | ✅ Complete | `m / 44' / coin_type' / 0' / 0 / 0` for transparent |
| BIP-39 | ✅ Complete | 12/18/24 words, optional passphrase |
| BIP-44 | ✅ Complete | Coin types 133 (mainnet), 1 (testnet) |
| ZIP-32 (Orchard) | ✅ Complete | Hierarchical hardened derivation |
| ZIP-244 | ✅ Complete | Shielded txid digest + transparent per-input digest |
| ZIP-316 | ✅ Complete | Unified Address with Orchard-only receiver |
| RFC 6979 | ✅ Complete | Deterministic nonce for ECDSA and (analogous) RedPallas |
| RFC 9380 | ✅ Complete | Pallas hash-to-curve via SWU + 3-isogeny |
| NIST SP 800-38G | ✅ Complete | FF1-AES-256 diversifier |

### Reference test vectors

Cross-checked against `librustzcash` via the 49 KAT vectors in
`lib/libzcash-orchard-c/tests/test_vectors.c`.

### Mainnet validation

Transaction `1c9eb6ca4ada67bf66452120d128ceacf2c0e21146de089e51694eb14db5466b`,
broadcast 2026-03-30, wallet birthday Zcash block height 3,290,915.
Evidence captured in `screenshots/mainnet_pair.png`,
`screenshots/mainnet_broadcast.png`, `screenshots/memo.png`.

---

## 13. Security Model

### Implemented mitigations

- **Memory zeroization** — all sensitive data (`sk`, `ask`, `nk`,
  `rivk`, `seed`, mnemonic, transparent SK) is wiped with `memzero()`
  immediately after use. The BIP-39 seed is zeroed at the end of each
  derivation; the transparent SK is zeroed when the signing session
  closes.
- **No key logging** — private keys are never printed, logged, or
  persisted to disk in cleartext.
- **Library-enforced sighash verification** — Orchard signing refuses
  to run unless the on-device ZIP-244 sighash has been recomputed and
  matched against the companion's value. The check is in the library,
  not in device-specific code; a hostile or buggy firmware port cannot
  bypass it.
- **Library-enforced transparent-digest verification** — the same
  pattern applies to transparent ECDSA signing: the device recomputes
  the transparent digest from the streamed inputs/outputs and matches
  it against both the sentinel value and the digest in the transaction
  metadata before any signature is emitted.
- **Network-mismatch check** — the session coin type, the transaction
  metadata coin type, and the recipient address prefix (`u` / `utest`)
  are all required to agree before signing.
- **BIP-39 passphrase** — supported but never persisted; must be
  re-entered every session.
- **Hardware RNG** — all cryptographic randomness comes from the
  STM32WB55 true RNG. No seed-based pseudorandom generators.

### Acknowledged limitations

- **Not audited.** No independent security review has been performed.
  The `Proof of Concept — not production-ready` disclaimer in
  `README.md` and `lib/libzcash-orchard-c/SECURITY.md` is intentional
  and remains in place until an audit is funded and complete.
- **`wallet.dat` confidentiality.** Mnemonic-on-SD encryption uses RC4
  with a K1/K2 scheme: K1 is a static literal compiled into the
  firmware; K2 is generated fresh per save and itself encrypted with
  K1. Because K1 is hardcoded, this is **obfuscation against casual
  inspection**, not confidentiality against an attacker with a copy
  of the firmware. A future revision should derive K1 from a user PIN
  or passphrase.
- **Single account, single address per pool.** The ZIP-32 Orchard
  account is fixed to 0; the transparent BIP-44 path is fixed to
  `m / 44' / coin_type' / 0' / 0 / 0`.
- **Sapling not supported on-device.** Sapling digest is accepted as a
  pre-computed 32-byte value in transaction metadata, but no Sapling
  spend authorization, key derivation, or note decryption is
  implemented on-device.
- **No PIN, no anti-phishing word, no secure element, no attestation.**

---

## 14. Coin Configuration

```c
// Mainnet
{ coin_type: 133, hrp: "u",     label: "ZEC",  path: "m_o/32'/133'/0'" }

// Testnet
{ coin_type: 1,   hrp: "utest", label: "TAZ",  path: "m_o/32'/1'/0'"   }
```

The session coin type, the transaction-metadata coin type, and the
recipient address prefix (`u` / `utest`) are cross-checked before any
signature is emitted; mismatch raises `HWP_ERR_NETWORK_MISMATCH (0x05)`.

---

## 15. Menu Structure

```
FlipZcash Wallet
  ├── View Address       Loads from wallet.dat, displays UA + QR
  ├── USB Serial Signer  HWP worker (sighash verify + RedPallas + ECDSA)
  ├── Keys (Advanced)    ak, nk, rivk in hex
  ├── Mnemonic           24 words (4 per screen)
  ├── Regenerate Wallet  New seed (with confirmation)
  ├── Import Seed        Word-by-word entry with autocomplete
  └── Settings
       ├── Network         Mainnet (ZEC) / Testnet (TAZ)
       ├── BIP39 Strength  128 / 192 / 256 bit
       └── BIP39 Passphrase On / Off
```

---

## 16. Future Optimizations

| # | Optimization | Status |
|---|---|---|
| 1 | **Montgomery multiplication.** Replace bit-by-bit Horner with Montgomery (O(522) → O(9) per limb). Could cut `fp_mul` cost by 50–70%. | Not implemented |
| 2 | **Windowed scalar multiplication (wNAF-4).** Reduce `pallas_point_mul` adds from ~128 to ~64. | Not implemented |
| 3 | **Precomputed Sinsemilla `S_i` points.** Eliminate the 51 `hash_to_curve` calls in `SinsemillaShortCommit`. | ✅ Implemented as `sinsemilla_s.bin` SD-card LUT — 15 min → 1.5 min |
| 4 | **Batch Montgomery-trick inversion** in `iso_map` and SWU. | Not implemented |
| 5 | **GLV endomorphism on Pallas** to halve scalar-multiplication cost. | Not implemented |
| 6 | **PIN-derived `wallet.dat` master key** to upgrade obfuscation to confidentiality. | Future revision |
| 7 | **Sapling support on-device** | Out of current scope |
