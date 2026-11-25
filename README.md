# keel_crypto

Zero-dependency C++20 cryptographic primitives built on `keel::keel` (Windows / Linux / WASM, compatible with `-fno-exceptions -fno-rtti`, verified under MSVC AddressSanitizer and cross-checked against OpenSSL 3.5 / 3.0 and PyCryptodome).

## Modules

- `keel/crypto/ct.h` — constant-time byte comparison (`ct_equal`), non-elidable memory wiping (`secure_zero`), constant-time selection, hex encoding/decoding (`to_hex`, `from_hex`).
- `keel/crypto/digest.h` — streaming & one-shot cryptographic digests: `MD2`, `MD5`, `SHA-1`, `SHA-224`, `SHA-256`, `SHA-384`, `SHA-512`, `SHA3-224`, `SHA3-256`, `SHA3-384`, `SHA3-512`, plus stack-allocated polymorphic `Digest`.
- `keel/crypto/sha3.h` — Keccak-f[1600] sponge (FIPS 202): `Sha3_224`, `Sha3_256`, `Sha3_384`, `Sha3_512`, and extendable-output functions `Shake128`, `Shake256` with incremental `squeeze`.
- `keel/crypto/blake.h` — `Blake2b` / `Blake2s` (RFC 7693, configurable output length and keyed MAC) and `Blake3` (streaming Merkle tree, standard / `keyed` / `derive_key` modes, arbitrary-length XOF with `seek`).
- `keel/crypto/hmac.h` — streaming & one-shot HMAC (RFC 2104 / RFC 4231) over any `DigestAlgorithm` (including SHA-3), with constant-time tag verification.
- `keel/crypto/kdf.h` — HKDF (RFC 5869) and PBKDF2-HMAC (RFC 2898 / RFC 6070).
- `keel/crypto/argon2.h` — memory-hard password KDF `Argon2id`, `Argon2i`, and `Argon2d` (RFC 9106 v1.3, with optional secret & associated data, wiping the full memory matrix on exit).
- `keel/crypto/aes.h` — constant-time algebraic GF($2^8$) AES-128/192/256 (FIPS-197) with CBC (raw & constant-time PKCS#7), CTR (NIST SP 800-38A), and GCM AEAD (NIST SP 800-38D).
- `keel/crypto/chacha20.h` — ChaCha20, HChaCha20, constant-time radix-$2^{26}$ Poly1305, ChaCha20-Poly1305 (RFC 8439), and XChaCha20-Poly1305 AEAD.
- `keel/crypto/curve25519.h` — portable constant-time X25519 Diffie-Hellman (RFC 7748, low-order rejection) and deterministic Ed25519 digital signatures (RFC 8032, strict canonical verification $y < p$, $S < L$).
- `keel/crypto/random.h` — OS-backed CSPRNG (`random_bytes`) and keypair generators (`generate_x25519_keypair`, `generate_ed25519_keypair`) with RAII secret wiping.
- `keel/crypto/box.h` — misuse-resistant high-level authenticated encryption: `secret_box_seal`/`open` (XChaCha20-Poly1305 with random 24-byte nonce) and `sealed_box_seal`/`open` (ephemeral X25519 + HKDF-SHA256 + XChaCha20-Poly1305).
- `keel/crypto.h` — umbrella header.

## Testing & Reference Verification

```bash
cmake -S . -B build
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure

# Differential verification against OpenSSL 3.5 / 3.0, Python hashlib/hmac, PyCryptodome, and BLAKE3 reference:
python tests/verify_reference.py build/Release/test_crypto.exe
```
