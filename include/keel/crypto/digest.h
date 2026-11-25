#pragma once

#include "keel/array.h"
#include "keel/core.h"
#include "keel/optional.h"
#include "keel/ref.h"
#include "keel/static_array.h"

namespace keel::crypto {

enum class DigestAlgorithm : u8 {
    Md2 = 0,
    Md5 = 1,
    Sha1 = 2,
    Sha224 = 3,
    Sha256 = 4,
    Sha384 = 5,
    Sha512 = 6,
};

inline constexpr usize kMaxDigestSize = 64u;
inline constexpr usize kMaxDigestBlockSize = 128u;

// Case-insensitive parser supporting canonical and compact names
// (e.g. "MD2", "MD5", "SHA-1"/"SHA1", "SHA-224"/"SHA224",
// "SHA-256"/"SHA256", "SHA-384"/"SHA384", "SHA-512"/"SHA512").
[[nodiscard]] Optional<DigestAlgorithm> parse_digest_algorithm(StringRef name) noexcept;

// Canonical standard name ("MD2", "MD5", "SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512").
[[nodiscard]] StringRef digest_algorithm_name(DigestAlgorithm alg) noexcept;

[[nodiscard]] usize digest_output_size(DigestAlgorithm alg) noexcept;
[[nodiscard]] usize digest_block_size(DigestAlgorithm alg) noexcept;

// ---------------------------------------------------------------------------
// MD2 (RFC 1319) — legacy compatibility
// ---------------------------------------------------------------------------
class Md2 {
public:
    static constexpr usize kDigestSize = 16u;
    static constexpr usize kBlockSize = 16u;

    Md2() noexcept;
    ~Md2() noexcept;
    Md2(const Md2&) noexcept = default;
    Md2& operator=(const Md2&) noexcept = default;

    void reset() noexcept;
    void update(const u8* data, usize len) noexcept;
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
    void transform(const u8 block[16]) noexcept;

    u8 m_state[48];
    u8 m_checksum[16];
    u8 m_buf[16];
    usize m_buf_len;
};

// ---------------------------------------------------------------------------
// MD5 (RFC 1321) — legacy compatibility
// ---------------------------------------------------------------------------
class Md5 {
public:
    static constexpr usize kDigestSize = 16u;
    static constexpr usize kBlockSize = 64u;

    Md5() noexcept;
    ~Md5() noexcept;
    Md5(const Md5&) noexcept = default;
    Md5& operator=(const Md5&) noexcept = default;

    void reset() noexcept;
    void update(const u8* data, usize len) noexcept;
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
    void transform(const u8 block[64]) noexcept;

    u32 m_state[4];
    u64 m_total_bytes;
    u8 m_buf[64];
    usize m_buf_len;
};

// ---------------------------------------------------------------------------
// SHA-1 (FIPS 180-4) — legacy / WebSocket / Git compatibility
// ---------------------------------------------------------------------------
class Sha1 {
public:
    static constexpr usize kDigestSize = 20u;
    static constexpr usize kBlockSize = 64u;

    Sha1() noexcept;
    ~Sha1() noexcept;
    Sha1(const Sha1&) noexcept = default;
    Sha1& operator=(const Sha1&) noexcept = default;

    void reset() noexcept;
    void update(const u8* data, usize len) noexcept;
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
    void transform(const u8 block[64]) noexcept;

    u32 m_state[5];
    u64 m_total_bytes;
    u8 m_buf[64];
    usize m_buf_len;
};

// ---------------------------------------------------------------------------
// SHA-256 (FIPS 180-4)
// ---------------------------------------------------------------------------
class Sha256 {
public:
    static constexpr usize kDigestSize = 32u;
    static constexpr usize kBlockSize = 64u;

    Sha256() noexcept;
    ~Sha256() noexcept;
    Sha256(const Sha256&) noexcept = default;
    Sha256& operator=(const Sha256&) noexcept = default;

    void reset() noexcept;
    void update(const u8* data, usize len) noexcept;
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
    friend class Sha224;
    void reset_with_iv(const u32 iv[8]) noexcept;
    void finalize_truncated(u8* out, usize out_bytes) noexcept;
    void transform(const u8 block[64]) noexcept;

    u32 m_state[8];
    u64 m_total_bytes;
    u8 m_buf[64];
    usize m_buf_len;
};

// ---------------------------------------------------------------------------
// SHA-224 (FIPS 180-4)
// ---------------------------------------------------------------------------
class Sha224 {
public:
    static constexpr usize kDigestSize = 28u;
    static constexpr usize kBlockSize = 64u;

    Sha224() noexcept;
    ~Sha224() noexcept;
    Sha224(const Sha224&) noexcept = default;
    Sha224& operator=(const Sha224&) noexcept = default;

    void reset() noexcept;
    void update(const u8* data, usize len) noexcept;
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
    Sha256 m_core;
};

// ---------------------------------------------------------------------------
// SHA-512 (FIPS 180-4)
// ---------------------------------------------------------------------------
class Sha512 {
public:
    static constexpr usize kDigestSize = 64u;
    static constexpr usize kBlockSize = 128u;

    Sha512() noexcept;
    ~Sha512() noexcept;
    Sha512(const Sha512&) noexcept = default;
    Sha512& operator=(const Sha512&) noexcept = default;

    void reset() noexcept;
    void update(const u8* data, usize len) noexcept;
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
    friend class Sha384;
    void reset_with_iv(const u64 iv[8]) noexcept;
    void finalize_truncated(u8* out, usize out_bytes) noexcept;
    void transform(const u8 block[128]) noexcept;

    u64 m_state[8];
    u64 m_total_lo;
    u64 m_total_hi;
    u8 m_buf[128];
    usize m_buf_len;
};

// ---------------------------------------------------------------------------
// SHA-384 (FIPS 180-4)
// ---------------------------------------------------------------------------
class Sha384 {
public:
    static constexpr usize kDigestSize = 48u;
    static constexpr usize kBlockSize = 128u;

    Sha384() noexcept;
    ~Sha384() noexcept;
    Sha384(const Sha384&) noexcept = default;
    Sha384& operator=(const Sha384&) noexcept = default;

    void reset() noexcept;
    void update(const u8* data, usize len) noexcept;
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
    Sha512 m_core;
};

// ---------------------------------------------------------------------------
// Stack-allocated polymorphic streaming Digest (zero heap allocations)
// ---------------------------------------------------------------------------
class Digest {
public:
    explicit Digest(DigestAlgorithm alg = DigestAlgorithm::Sha256) noexcept;
    ~Digest() noexcept;
    Digest(const Digest& other) noexcept;
    Digest& operator=(const Digest& other) noexcept;

    [[nodiscard]] static Optional<Digest> create(StringRef alg_name) noexcept;

    [[nodiscard]] DigestAlgorithm algorithm() const noexcept { return m_alg; }
    [[nodiscard]] StringRef algorithm_name() const noexcept { return digest_algorithm_name(m_alg); }
    [[nodiscard]] usize output_size() const noexcept { return digest_output_size(m_alg); }
    [[nodiscard]] usize block_size() const noexcept { return digest_block_size(m_alg); }

    void reset() noexcept;
    void update(const u8* data, usize len) noexcept;
    void update(ArrayRef<u8> data) noexcept { update(data.data(), data.size()); }
    void update(StringRef data) noexcept {
        update(reinterpret_cast<const u8*>(data.data()), data.size());
    }

    // Writes output_size() bytes into `out` (must have size >= output_size()) and resets state.
    // Returns number of bytes written (0 if out.size() < output_size()).
    usize finalize(MutArrayRef<u8> out) noexcept;

    // Allocates an Array<u8> of length output_size() and resets state.
    [[nodiscard]] Array<u8> finalize(Allocator* alloc = nullptr);

    [[nodiscard]] static Array<u8> hash(DigestAlgorithm alg, ArrayRef<u8> data, Allocator* alloc = nullptr);

private:
    union Storage {
        Md2 md2;
        Md5 md5;
        Sha1 sha1;
        Sha224 sha224;
        Sha256 sha256;
        Sha384 sha384;
        Sha512 sha512;
        Storage() noexcept {}
        ~Storage() noexcept {}
    };

    void construct_active() noexcept;
    void copy_active_from(const Digest& other) noexcept;
    void destroy_active() noexcept;

    DigestAlgorithm m_alg;
    Storage m_storage;
};

// Convenience one-shot helpers
[[nodiscard]] inline StaticArray<u8, 16> md2(ArrayRef<u8> data) noexcept { return Md2::hash(data); }
[[nodiscard]] inline StaticArray<u8, 16> md5(ArrayRef<u8> data) noexcept { return Md5::hash(data); }
[[nodiscard]] inline StaticArray<u8, 20> sha1(ArrayRef<u8> data) noexcept { return Sha1::hash(data); }
[[nodiscard]] inline StaticArray<u8, 28> sha224(ArrayRef<u8> data) noexcept { return Sha224::hash(data); }
[[nodiscard]] inline StaticArray<u8, 32> sha256(ArrayRef<u8> data) noexcept { return Sha256::hash(data); }
[[nodiscard]] inline StaticArray<u8, 48> sha384(ArrayRef<u8> data) noexcept { return Sha384::hash(data); }
[[nodiscard]] inline StaticArray<u8, 64> sha512(ArrayRef<u8> data) noexcept { return Sha512::hash(data); }

[[nodiscard]] inline StaticArray<u8, 16> md2(StringRef data) noexcept { return Md2::hash(data); }
[[nodiscard]] inline StaticArray<u8, 16> md5(StringRef data) noexcept { return Md5::hash(data); }
[[nodiscard]] inline StaticArray<u8, 20> sha1(StringRef data) noexcept { return Sha1::hash(data); }
[[nodiscard]] inline StaticArray<u8, 28> sha224(StringRef data) noexcept { return Sha224::hash(data); }
[[nodiscard]] inline StaticArray<u8, 32> sha256(StringRef data) noexcept { return Sha256::hash(data); }
[[nodiscard]] inline StaticArray<u8, 48> sha384(StringRef data) noexcept { return Sha384::hash(data); }
[[nodiscard]] inline StaticArray<u8, 64> sha512(StringRef data) noexcept { return Sha512::hash(data); }

} // namespace keel::crypto
