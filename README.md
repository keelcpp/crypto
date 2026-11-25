# keel_crypto

Zero-dependency C++20 cryptographic primitives built on `keel::keel` (Windows / Linux / WASM, compatible with `-fno-exceptions -fno-rtti`).

## Modules

- `keel/crypto/ct.h` — constant-time byte comparison (`ct_equal`), non-elidable memory wiping (`secure_zero`), constant-time selection, hex encoding/decoding (`to_hex`, `from_hex`).
- `keel/crypto/digest.h` — streaming & one-shot cryptographic digests: `MD2`, `MD5`, `SHA-1`, `SHA-224`, `SHA-256`, `SHA-384`, `SHA-512`, plus stack-allocated polymorphic `Digest`.
- `keel/crypto/hmac.h` — streaming & one-shot HMAC (RFC 2104 / RFC 4231) over any `DigestAlgorithm`, with constant-time tag verification.
- `keel/crypto/kdf.h` — HKDF (RFC 5869) and PBKDF2-HMAC (RFC 2898 / RFC 6070).
- `keel/crypto.h` — umbrella header.
