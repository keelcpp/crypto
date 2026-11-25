#pragma once

#include "keel/array.h"
#include "keel/core.h"
#include "keel/optional.h"
#include "keel/ref.h"

namespace keel::crypto {

enum class Argon2Type : u32 {
    Argon2d = 0u,
    Argon2i = 1u,
    Argon2id = 2u,
};

struct Argon2Params {
    Argon2Type type = Argon2Type::Argon2id;
    u32 memory_kib = 65536u;   // Memory cost in KiB (>= 8 * parallelism)
    u32 iterations = 3u;       // Time cost / passes (>= 1)
    u32 parallelism = 1u;      // Lanes (>= 1)
    u32 tag_len = 32u;         // Output tag length in bytes (>= 4)
};

// RFC 9106 Argon2 (v1.3 — Argon2id / Argon2i / Argon2d).
// Supports optional secret key `secret` and `associated_data`.
// Returns empty Optional on invalid parameters.
[[nodiscard]] Optional<Array<u8>> argon2(const Argon2Params& params,
                                         ArrayRef<u8> password,
                                         ArrayRef<u8> salt,
                                         ArrayRef<u8> secret = {},
                                         ArrayRef<u8> associated_data = {},
                                         Allocator* alloc = nullptr);

[[nodiscard]] inline Optional<Array<u8>> argon2id(ArrayRef<u8> password,
                                                  ArrayRef<u8> salt,
                                                  u32 memory_kib = 65536u,
                                                  u32 iterations = 3u,
                                                  u32 parallelism = 1u,
                                                  u32 tag_len = 32u,
                                                  Allocator* alloc = nullptr) {
    Argon2Params p{};
    p.type = Argon2Type::Argon2id;
    p.memory_kib = memory_kib;
    p.iterations = iterations;
    p.parallelism = parallelism;
    p.tag_len = tag_len;
    return argon2(p, password, salt, {}, {}, alloc);
}

} // namespace keel::crypto
