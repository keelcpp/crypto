#include "keel/crypto/random.h"

#include "keel/crypto/ct.h"
#include "keel/crypto/curve25519.h"
#include "keel/os_random.h"

namespace keel::crypto {

bool random_bytes(MutArrayRef<u8> out) noexcept {
    if (out.empty()) return true;
    const Error err = os_random_bytes(out);
    return err.is_ok();
}

bool random_bytes(u8* out, usize len) noexcept {
    if (len == 0u) return true;
    if (!out) return false;
    return random_bytes(MutArrayRef<u8>(out, len));
}

X25519KeyPair::~X25519KeyPair() noexcept {
    secure_zero(secret_key.data(), secret_key.size());
}

Ed25519KeyPair::~Ed25519KeyPair() noexcept {
    secure_zero(seed.data(), seed.size());
}

Optional<X25519KeyPair> generate_x25519_keypair() noexcept {
    X25519KeyPair kp{};
    if (!random_bytes(kp.secret_key.as_mut_ref())) return Optional<X25519KeyPair>{};
    x25519_public_key(kp.secret_key.data(), kp.public_key.data());
    return kp;
}

Optional<Ed25519KeyPair> generate_ed25519_keypair() noexcept {
    Ed25519KeyPair kp{};
    if (!random_bytes(kp.seed.as_mut_ref())) return Optional<Ed25519KeyPair>{};
    ed25519_public_key(kp.seed.data(), kp.public_key.data());
    return kp;
}

} // namespace keel::crypto
