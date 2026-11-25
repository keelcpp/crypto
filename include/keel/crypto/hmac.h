#pragma once

#include "keel/array.h"
#include "keel/core.h"
#include "keel/crypto/digest.h"
#include "keel/ref.h"

namespace keel::crypto {

// Streaming HMAC (RFC 2104 / RFC 4231) over any DigestAlgorithm.
class Hmac {
public:
    Hmac(DigestAlgorithm alg, ArrayRef<u8> key) noexcept;
    Hmac(DigestAlgorithm alg, StringRef key) noexcept
        : Hmac(alg, ArrayRef<u8>(reinterpret_cast<const u8*>(key.data()), key.size())) {}
    ~Hmac() noexcept;
    Hmac(const Hmac&) noexcept = default;
    Hmac& operator=(const Hmac&) noexcept = default;

    [[nodiscard]] DigestAlgorithm algorithm() const noexcept { return m_alg; }
    [[nodiscard]] usize output_size() const noexcept { return digest_output_size(m_alg); }

    // Reset streaming state while retaining the prepared key.
    void reset() noexcept;

    void update(const u8* data, usize len) noexcept;
    void update(ArrayRef<u8> data) noexcept { update(data.data(), data.size()); }
    void update(StringRef data) noexcept {
        update(reinterpret_cast<const u8*>(data.data()), data.size());
    }

    // Finalize MAC into `out` (must have size >= output_size()) and reset for next message.
    usize finalize(MutArrayRef<u8> out) noexcept;
    [[nodiscard]] Array<u8> finalize(Allocator* alloc = nullptr);

    [[nodiscard]] static Array<u8> compute(
        DigestAlgorithm alg, ArrayRef<u8> key, ArrayRef<u8> data, Allocator* alloc = nullptr);

    // Constant-time MAC verification.
    [[nodiscard]] static bool verify(
        DigestAlgorithm alg, ArrayRef<u8> key, ArrayRef<u8> data, ArrayRef<u8> expected_tag) noexcept;

private:
    DigestAlgorithm m_alg;
    u8 m_ipad[kMaxDigestBlockSize];
    u8 m_opad[kMaxDigestBlockSize];
    usize m_block_size;
    Digest m_inner;
};

} // namespace keel::crypto
