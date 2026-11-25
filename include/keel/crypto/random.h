#pragma once

#include "keel/core.h"
#include "keel/optional.h"
#include "keel/ref.h"
#include "keel/static_array.h"

namespace keel::crypto {

// ---------------------------------------------------------------------------
// Cryptographically secure OS randomness & keypair generation (via keel::os_random)
// ---------------------------------------------------------------------------

// Fills `out` with CSPRNG bytes from the host OS. Returns false on OS RNG failure.
[[nodiscard]] bool random_bytes(MutArrayRef<u8> out) noexcept;
[[nodiscard]] bool random_bytes(u8* out, usize len) noexcept;

struct X25519KeyPair {
    StaticArray<u8, 32u> secret_key{};
    StaticArray<u8, 32u> public_key{};

    ~X25519KeyPair() noexcept;
    X25519KeyPair() noexcept = default;
    X25519KeyPair(const X25519KeyPair&) noexcept = default;
    X25519KeyPair& operator=(const X25519KeyPair&) noexcept = default;
};

struct Ed25519KeyPair {
    StaticArray<u8, 32u> seed{};
    StaticArray<u8, 32u> public_key{};

    ~Ed25519KeyPair() noexcept;
    Ed25519KeyPair() noexcept = default;
    Ed25519KeyPair(const Ed25519KeyPair&) noexcept = default;
    Ed25519KeyPair& operator=(const Ed25519KeyPair&) noexcept = default;
};

[[nodiscard]] Optional<X25519KeyPair> generate_x25519_keypair() noexcept;
[[nodiscard]] Optional<Ed25519KeyPair> generate_ed25519_keypair() noexcept;

} // namespace keel::crypto
