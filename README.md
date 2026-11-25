# keel_crypto

Zero-dependency C++20 cryptographic primitives built on `keel::keel` (Windows / Linux / WASM, compatible with `-fno-exceptions -fno-rtti`).

## Modules

- `keel/crypto/ct.h` — constant-time byte comparison (`ct_equal`), non-elidable memory wiping (`secure_zero`), constant-time selection, hex encoding/decoding (`to_hex`, `from_hex`).
- `keel/crypto/digest.h` — streaming & one-shot cryptographic digests: `MD2`, `MD5`, `SHA-1`, `SHA-224`, `SHA-256`, `SHA-384`, `SHA-512`, plus stack-allocated polymorphic `Digest`.
- `keel/crypto/hmac.h` — streaming & one-shot HMAC (RFC 2104 / RFC 4231) over any `DigestAlgorithm`, with constant-time tag verification.
- `keel/crypto/kdf.h` — HKDF (RFC 5869) and PBKDF2-HMAC (RFC 2898 / RFC 6070).
- `keel/crypto/aes.h` — constant-time algebraic GF($2^8$) AES-128/192/256 (FIPS-197) with CBC (raw & constant-time PKCS#7), CTR (NIST SP 800-38A), and GCM AEAD (NIST SP 800-38D).
- `keel/crypto/chacha20.h` — ChaCha20, HChaCha20, constant-time radix-$2^{26}$ Poly1305, ChaCha20-Poly1305 (RFC 8439), and XChaCha20-Poly1305 AEAD.
- `keel/crypto/curve25519.h` — portable constant-time X25519 Diffie-Hellman (RFC 7748) and deterministic Ed25519 digital signatures (RFC 8032) with strict canonical verification ($y < p$, $S < L$).
- `keel/crypto.h` — umbrella header.
