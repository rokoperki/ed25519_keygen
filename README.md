# ed25519_keygen

A from-scratch implementation of the full cryptographic pipeline from a BIP-39 mnemonic seed phrase to a Solana Ed25519 keypair — built for learning, not production.

---

## What it does

```
Entropy (128 bits)
    │  getrandom (OS secure RNG)
    ▼
Mnemonic (12 words)
    │  SHA-256 checksum → 11-bit chunks → BIP-39 wordlist
    ▼
Seed (64 bytes)
    │  PBKDF2-HMAC-SHA512, 2048 iterations, salt = "mnemonic"
    ▼
Private key (32 bytes)
    │  SLIP-0010 HMAC key derivation  m/44'/501'/0'/0'
    ▼
Public key (32 bytes)
    │  SHA-512(seed) → clamp → scalar × G  (Ed25519)
    ▼
Solana address (base58)
```

---

## Running

```bash
cargo run
```

Example output:

```
────────────────────────────────────────────────────────────
  STEP 1 — Entropy (128 bits of randomness)
────────────────────────────────────────────────────────────
  Raw bytes : [51, 110, 218, ...]
  Hex       : 336eda43b5cf5c240b55fd8ffc894450

────────────────────────────────────────────────────────────
  STEP 2 — BIP-39: entropy → mnemonic
────────────────────────────────────────────────────────────
  ┌─────────────────────────────────────────┐
  │  cricket item movie high volume bamboo ...  │
  └─────────────────────────────────────────┘

────────────────────────────────────────────────────────────
  STEP 3 — PBKDF2-HMAC-SHA512 (2048 iterations)
────────────────────────────────────────────────────────────
  Seed (64 bytes):
    7c2144b919faaa61...
    f4bb9d0bbff7cf75...

────────────────────────────────────────────────────────────
  STEP 4 — SLIP-0010 key derivation (m/44'/501'/0'/0')
────────────────────────────────────────────────────────────
  Private key: e57b5826135373d2...

────────────────────────────────────────────────────────────
  STEP 5 — Ed25519: private key → public key
────────────────────────────────────────────────────────────
  Public key: 7fd06631070cfdbd...

────────────────────────────────────────────────────────────
  RESULT — Solana wallet address
────────────────────────────────────────────────────────────

  9bw63NYvkY1ce3ALH3XhesfE8Nc2cPv1xwXj6zFJkpsc
```

---

## Testing

```bash
cargo test
```

The test suite verifies each layer:

| Test | What it checks |
|---|---|
| `test_base_point_encode` | Base point G encodes to the known compressed form |
| `test_identity_add` | Identity + G = G |
| `test_double_vs_add` | G + G = 2G (add and double are consistent) |
| `test_known_vector` | Full pipeline output matches `ed25519-dalek` for the "abandon ×11 about" mnemonic |

---

## Implementation

Every primitive is hand-rolled — no crypto library dependencies in production code.

### `sha256.rs`
SHA-256 from scratch. Used for the BIP-39 checksum.

### `sha512.rs`
SHA-512 from scratch. Used inside HMAC and Ed25519 key expansion.
Same structure as SHA-256 but with 64-bit words, 80 rounds, and 128-byte blocks.

### `entropy.rs`
Calls `getrandom` (OS secure RNG) to produce 16 bytes of cryptographic randomness.

### `bip_39.rs`
Converts entropy bytes to a 12-word mnemonic:
1. Compute SHA-256 checksum, take first 4 bits
2. Append checksum bits to entropy → 132 bits
3. Split into twelve 11-bit chunks
4. Map each chunk to a word in the 2048-word BIP-39 wordlist

### `pbkdf2.rs`
PBKDF2-HMAC-SHA512 with 2048 iterations.
`U1 = HMAC(password, salt ‖ block)`, then `U2 = HMAC(password, U1)`, …, XOR all together.

### `slip_0010.rs`
Hierarchical key derivation for Ed25519 following SLIP-0010.
Master key: `HMAC-SHA512("ed25519 seed", bip39_seed)`.
Each hardened child: `HMAC-SHA512(chain_code, 0x00 ‖ key ‖ (index | 0x80000000))`.
Path used: `m/44'/501'/0'/0'` (Solana BIP-44 standard).

### `field_element.rs`
Arithmetic modulo `p = 2²⁵⁵ − 19` using five 51-bit limbs (radix 2⁵¹).

| Operation | Technique |
|---|---|
| `add` | Pairwise add + carry propagation + 2²⁵⁵ ≡ 19 fold |
| `sub` | Add 2p before subtracting to prevent underflow |
| `mul` | Schoolbook with `u128` intermediates, fold high limbs × 19 |
| `invert` | `a^(p−2)` via 250-squaring addition chain (Fermat's little theorem) |
| `to_bytes` / `from_bytes` | 32-byte little-endian packing across 51-bit limb boundaries |

### `ed25519.rs`
Ed25519 curve: `-x² + y² = 1 + d·x²·y²` over GF(2²⁵⁵ − 19).

Points use **extended coordinates** `(X:Y:Z:T)` where `x = X/Z`, `y = Y/Z`, `T = XY/Z`.

| Operation | Formula set |
|---|---|
| `add` | add-2008-hwcd (unified, works for any two points) |
| `double` | dbl-2008-hwcd optimised for `a = −1` |
| `scalar_mul` | Double-and-add, LSB to MSB on 32-byte little-endian scalar |
| `encode` | y-coordinate little-endian, sign of x in top bit of byte 31 |

Key generation (`public_key_from_seed`):
1. `h = SHA-512(private_seed)` — 64 bytes
2. `scalar = h[0..32]` with clamping: clear bits 0–2 and 255, set bit 254
3. `public_key = scalar × G` → encode

---

## Specifications

- [BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) — Mnemonic phrases
- [BIP-44](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki) — HD wallet paths
- [SLIP-0010](https://github.com/satoshilabs/slips/blob/master/slip-0010.md) — Ed25519 key derivation
- [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) — Ed25519 signing

---

> Built for educational purposes. Do not use hand-rolled cryptography in production.
