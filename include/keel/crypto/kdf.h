#pragma once

#include "keel/array.h"
#include "keel/core.h"
#include "keel/crypto/digest.h"
#include "keel/optional.h"
#include "keel/ref.h"

namespace keel::crypto {

// HKDF-Extract (RFC 5869 Section 2.2): PRK = HMAC-Hash(salt, IKM).
// If salt is empty, a zero-filled buffer of HashLen bytes is used.
[[nodiscard]] Array<u8> hkdf_extract(
    DigestAlgorithm alg, ArrayRef<u8> salt, ArrayRef<u8> ikm, Allocator* alloc = nullptr);

// HKDF-Expand (RFC 5869 Section 2.3): derives `out_len` bytes from PRK and info.
// Returns none if out_len > 255 * HashLen or prk.size() < HashLen.
[[nodiscard]] Optional<Array<u8>> hkdf_expand(
    DigestAlgorithm alg,
    ArrayRef<u8> prk,
    ArrayRef<u8> info,
    usize out_len,
    Allocator* alloc = nullptr);

// Full HKDF (Extract + Expand, RFC 5869).
// Returns none if out_len > 255 * HashLen.
[[nodiscard]] Optional<Array<u8>> hkdf(
    DigestAlgorithm alg,
    ArrayRef<u8> salt,
    ArrayRef<u8> ikm,
    ArrayRef<u8> info,
    usize out_len,
    Allocator* alloc = nullptr);

// PBKDF2-HMAC (RFC 2898 / RFC 6070).
// Returns none if iterations == 0.
[[nodiscard]] Optional<Array<u8>> pbkdf2_hmac(
    DigestAlgorithm alg,
    ArrayRef<u8> password,
    ArrayRef<u8> salt,
    u32 iterations,
    usize out_len,
    Allocator* alloc = nullptr);

} // namespace keel::crypto
