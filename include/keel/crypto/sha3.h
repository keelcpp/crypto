#pragma once

#include "keel/array.h"
#include "keel/core.h"
#include "keel/ref.h"
#include "keel/static_array.h"

namespace keel::crypto {

// ---------------------------------------------------------------------------
// Keccak-f[1600] sponge core (FIPS 202) shared by SHA-3 and SHAKE128/256.
// ---------------------------------------------------------------------------
namespace detail {

class KeccakSponge {
public:
    KeccakSponge() noexcept = default;
    ~KeccakSponge() noexcept;
    KeccakSponge(const KeccakSponge&) noexcept = default;
    KeccakSponge& operator=(const KeccakSponge&) noexcept = default;

    void reset(usize rate_bytes, u8 domain_pad) noexcept;
    void absorb(const u8* data, usize len) noexcept;
    void finalize_absorb() noexcept;
    void squeeze(u8* out, usize len) noexcept;

private:
    void permute() noexcept;

    u64 m_state[25] = {};
    usize m_rate = 136u;
    usize m_pos = 0u;
    u8 m_pad = 0x06u;
    bool m_squeezing = false;
};

} // namespace detail

// ---------------------------------------------------------------------------
// SHA3-224 / SHA3-256 / SHA3-384 / SHA3-512 (FIPS 202)
// ---------------------------------------------------------------------------
class Sha3_224 {
public:
    static constexpr usize kDigestSize = 28u;
    static constexpr usize kBlockSize = 144u;

    Sha3_224() noexcept { reset(); }
    void reset() noexcept { m_sponge.reset(kBlockSize, 0x06u); }
    void update(const u8* data, usize len) noexcept { m_sponge.absorb(data, len); }
    void update(ArrayRef<u8> data) noexcept { update(data.data(), data.size()); }
    void update(StringRef data) noexcept {
        update(reinterpret_cast<const u8*>(data.data()), data.size());
    }
    void finalize(u8* out) noexcept;
    [[nodiscard]] StaticArray<u8, kDigestSize> finalize() noexcept;
    [[nodiscard]] static StaticArray<u8, kDigestSize> hash(ArrayRef<u8> data) noexcept;
    [[nodiscard]] static StaticArray<u8, kDigestSize> hash(StringRef data) noexcept {
        return hash(ArrayRef<u8>(reinterpret_cast<const u8*>(data.data()), data.size()));
    }

private:
    detail::KeccakSponge m_sponge;
};

class Sha3_256 {
public:
    static constexpr usize kDigestSize = 32u;
    static constexpr usize kBlockSize = 136u;

    Sha3_256() noexcept { reset(); }
    void reset() noexcept { m_sponge.reset(kBlockSize, 0x06u); }
    void update(const u8* data, usize len) noexcept { m_sponge.absorb(data, len); }
    void update(ArrayRef<u8> data) noexcept { update(data.data(), data.size()); }
    void update(StringRef data) noexcept {
        update(reinterpret_cast<const u8*>(data.data()), data.size());
    }
    void finalize(u8* out) noexcept;
    [[nodiscard]] StaticArray<u8, kDigestSize> finalize() noexcept;
    [[nodiscard]] static StaticArray<u8, kDigestSize> hash(ArrayRef<u8> data) noexcept;
    [[nodiscard]] static StaticArray<u8, kDigestSize> hash(StringRef data) noexcept {
        return hash(ArrayRef<u8>(reinterpret_cast<const u8*>(data.data()), data.size()));
    }

private:
    detail::KeccakSponge m_sponge;
};

class Sha3_384 {
public:
    static constexpr usize kDigestSize = 48u;
    static constexpr usize kBlockSize = 104u;

    Sha3_384() noexcept { reset(); }
    void reset() noexcept { m_sponge.reset(kBlockSize, 0x06u); }
    void update(const u8* data, usize len) noexcept { m_sponge.absorb(data, len); }
    void update(ArrayRef<u8> data) noexcept { update(data.data(), data.size()); }
    void update(StringRef data) noexcept {
        update(reinterpret_cast<const u8*>(data.data()), data.size());
    }
    void finalize(u8* out) noexcept;
    [[nodiscard]] StaticArray<u8, kDigestSize> finalize() noexcept;
    [[nodiscard]] static StaticArray<u8, kDigestSize> hash(ArrayRef<u8> data) noexcept;
    [[nodiscard]] static StaticArray<u8, kDigestSize> hash(StringRef data) noexcept {
        return hash(ArrayRef<u8>(reinterpret_cast<const u8*>(data.data()), data.size()));
    }

private:
    detail::KeccakSponge m_sponge;
};

class Sha3_512 {
public:
    static constexpr usize kDigestSize = 64u;
    static constexpr usize kBlockSize = 72u;

    Sha3_512() noexcept { reset(); }
    void reset() noexcept { m_sponge.reset(kBlockSize, 0x06u); }
    void update(const u8* data, usize len) noexcept { m_sponge.absorb(data, len); }
    void update(ArrayRef<u8> data) noexcept { update(data.data(), data.size()); }
    void update(StringRef data) noexcept {
        update(reinterpret_cast<const u8*>(data.data()), data.size());
    }
    void finalize(u8* out) noexcept;
    [[nodiscard]] StaticArray<u8, kDigestSize> finalize() noexcept;
    [[nodiscard]] static StaticArray<u8, kDigestSize> hash(ArrayRef<u8> data) noexcept;
    [[nodiscard]] static StaticArray<u8, kDigestSize> hash(StringRef data) noexcept {
        return hash(ArrayRef<u8>(reinterpret_cast<const u8*>(data.data()), data.size()));
    }

private:
    detail::KeccakSponge m_sponge;
};

// ---------------------------------------------------------------------------
// SHAKE128 / SHAKE256 extendable-output functions (FIPS 202)
// Supports incremental update() followed by one or more squeeze() calls.
// ---------------------------------------------------------------------------
class Shake128 {
public:
    static constexpr usize kRateBytes = 168u;

    Shake128() noexcept { reset(); }
    void reset() noexcept { m_sponge.reset(kRateBytes, 0x1Fu); }
    void update(const u8* data, usize len) noexcept { m_sponge.absorb(data, len); }
    void update(ArrayRef<u8> data) noexcept { update(data.data(), data.size()); }
    void update(StringRef data) noexcept {
        update(reinterpret_cast<const u8*>(data.data()), data.size());
    }
    void squeeze(u8* out, usize len) noexcept { m_sponge.squeeze(out, len); }
    void squeeze(MutArrayRef<u8> out) noexcept { squeeze(out.data(), out.size()); }
    [[nodiscard]] static Array<u8> xof(ArrayRef<u8> data, usize out_len, Allocator* alloc = nullptr);

private:
    detail::KeccakSponge m_sponge;
};

class Shake256 {
public:
    static constexpr usize kRateBytes = 136u;

    Shake256() noexcept { reset(); }
    void reset() noexcept { m_sponge.reset(kRateBytes, 0x1Fu); }
    void update(const u8* data, usize len) noexcept { m_sponge.absorb(data, len); }
    void update(ArrayRef<u8> data) noexcept { update(data.data(), data.size()); }
    void update(StringRef data) noexcept {
        update(reinterpret_cast<const u8*>(data.data()), data.size());
    }
    void squeeze(u8* out, usize len) noexcept { m_sponge.squeeze(out, len); }
    void squeeze(MutArrayRef<u8> out) noexcept { squeeze(out.data(), out.size()); }
    [[nodiscard]] static Array<u8> xof(ArrayRef<u8> data, usize out_len, Allocator* alloc = nullptr);

private:
    detail::KeccakSponge m_sponge;
};

// Convenience one-shot helpers
[[nodiscard]] inline StaticArray<u8, 28u> sha3_224(ArrayRef<u8> data) noexcept { return Sha3_224::hash(data); }
[[nodiscard]] inline StaticArray<u8, 32u> sha3_256(ArrayRef<u8> data) noexcept { return Sha3_256::hash(data); }
[[nodiscard]] inline StaticArray<u8, 48u> sha3_384(ArrayRef<u8> data) noexcept { return Sha3_384::hash(data); }
[[nodiscard]] inline StaticArray<u8, 64u> sha3_512(ArrayRef<u8> data) noexcept { return Sha3_512::hash(data); }
[[nodiscard]] inline StaticArray<u8, 28u> sha3_224(StringRef data) noexcept { return Sha3_224::hash(data); }
[[nodiscard]] inline StaticArray<u8, 32u> sha3_256(StringRef data) noexcept { return Sha3_256::hash(data); }
[[nodiscard]] inline StaticArray<u8, 48u> sha3_384(StringRef data) noexcept { return Sha3_384::hash(data); }
[[nodiscard]] inline StaticArray<u8, 64u> sha3_512(StringRef data) noexcept { return Sha3_512::hash(data); }

[[nodiscard]] inline Array<u8> shake128(ArrayRef<u8> data, usize out_len, Allocator* alloc = nullptr) {
    return Shake128::xof(data, out_len, alloc);
}
[[nodiscard]] inline Array<u8> shake256(ArrayRef<u8> data, usize out_len, Allocator* alloc = nullptr) {
    return Shake256::xof(data, out_len, alloc);
}

} // namespace keel::crypto
