#pragma once

#include "keel/array.h"
#include "keel/core.h"
#include "keel/ref.h"
#include "keel/static_array.h"

namespace keel::crypto {

// ---------------------------------------------------------------------------
// BLAKE2b (RFC 7693) — 64-bit, output 1..64 bytes, optional key 0..64 bytes
// ---------------------------------------------------------------------------
class Blake2b {
public:
    static constexpr usize kBlockSize = 128u;
    static constexpr usize kMaxDigestSize = 64u;
    static constexpr usize kMaxKeySize = 64u;

    explicit Blake2b(usize out_len = 64u, ArrayRef<u8> key = {}) noexcept;
    ~Blake2b() noexcept;
    Blake2b(const Blake2b&) noexcept = default;
    Blake2b& operator=(const Blake2b&) noexcept = default;

    // Returns false if out_len not in [1, 64] or key.size() > 64.
    bool init(usize out_len = 64u, ArrayRef<u8> key = {}) noexcept;
    void update(const u8* data, usize len) noexcept;
    void update(ArrayRef<u8> data) noexcept { update(data.data(), data.size()); }
    void update(StringRef data) noexcept {
        update(reinterpret_cast<const u8*>(data.data()), data.size());
    }
    void finalize(u8* out) noexcept;
    [[nodiscard]] Array<u8> finalize(Allocator* alloc = nullptr);

    [[nodiscard]] usize output_size() const noexcept { return m_out_len; }

    [[nodiscard]] static Array<u8> hash(ArrayRef<u8> data, usize out_len = 64u,
                                        ArrayRef<u8> key = {}, Allocator* alloc = nullptr);

private:
    void compress(const u8 block[128], bool is_last) noexcept;

    u64 m_h[8] = {};
    u64 m_t[2] = {};
    u8 m_buf[128] = {};
    usize m_buf_len = 0u;
    usize m_out_len = 64u;
};

// ---------------------------------------------------------------------------
// BLAKE2s (RFC 7693) — 32-bit, output 1..32 bytes, optional key 0..32 bytes
// ---------------------------------------------------------------------------
class Blake2s {
public:
    static constexpr usize kBlockSize = 64u;
    static constexpr usize kMaxDigestSize = 32u;
    static constexpr usize kMaxKeySize = 32u;

    explicit Blake2s(usize out_len = 32u, ArrayRef<u8> key = {}) noexcept;
    ~Blake2s() noexcept;
    Blake2s(const Blake2s&) noexcept = default;
    Blake2s& operator=(const Blake2s&) noexcept = default;

    // Returns false if out_len not in [1, 32] or key.size() > 32.
    bool init(usize out_len = 32u, ArrayRef<u8> key = {}) noexcept;
    void update(const u8* data, usize len) noexcept;
    void update(ArrayRef<u8> data) noexcept { update(data.data(), data.size()); }
    void update(StringRef data) noexcept {
        update(reinterpret_cast<const u8*>(data.data()), data.size());
    }
    void finalize(u8* out) noexcept;
    [[nodiscard]] Array<u8> finalize(Allocator* alloc = nullptr);

    [[nodiscard]] usize output_size() const noexcept { return m_out_len; }

    [[nodiscard]] static Array<u8> hash(ArrayRef<u8> data, usize out_len = 32u,
                                        ArrayRef<u8> key = {}, Allocator* alloc = nullptr);

private:
    void compress(const u8 block[64], bool is_last) noexcept;

    u32 m_h[8] = {};
    u32 m_t[2] = {};
    u8 m_buf[64] = {};
    usize m_buf_len = 0u;
    usize m_out_len = 32u;
};

// ---------------------------------------------------------------------------
// BLAKE3 — hash, keyed MAC (32-byte key), and key derivation (derive_key),
// with full Merkle tree streaming and arbitrary-length XOF output.
// ---------------------------------------------------------------------------
class Blake3 {
public:
    static constexpr usize kDefaultDigestSize = 32u;
    static constexpr usize kKeySize = 32u;
    static constexpr usize kBlockSize = 64u;
    static constexpr usize kChunkSize = 1024u;

    Blake3() noexcept;
    ~Blake3() noexcept;
    Blake3(const Blake3&) noexcept = default;
    Blake3& operator=(const Blake3&) noexcept = default;

    [[nodiscard]] static Blake3 keyed(const u8 key[32]) noexcept;
    [[nodiscard]] static Blake3 derive_key(StringRef context) noexcept;

    void reset() noexcept;
    void update(const u8* data, usize len) noexcept;
    void update(ArrayRef<u8> data) noexcept { update(data.data(), data.size()); }
    void update(StringRef data) noexcept {
        update(reinterpret_cast<const u8*>(data.data()), data.size());
    }

    // Writes `out_len` XOF bytes starting at byte offset `seek` (default 0).
    // Does not mutate state, so finalize may be called multiple times.
    void finalize(u8* out, usize out_len, u64 seek = 0u) const noexcept;
    [[nodiscard]] StaticArray<u8, 32u> finalize() const noexcept;
    [[nodiscard]] Array<u8> finalize_xof(usize out_len, u64 seek = 0u,
                                         Allocator* alloc = nullptr) const;

    [[nodiscard]] static StaticArray<u8, 32u> hash(ArrayRef<u8> data) noexcept;
    [[nodiscard]] static StaticArray<u8, 32u> hash(StringRef data) noexcept {
        return hash(ArrayRef<u8>(reinterpret_cast<const u8*>(data.data()), data.size()));
    }
    [[nodiscard]] static StaticArray<u8, 32u> keyed_hash(const u8 key[32],
                                                         ArrayRef<u8> data) noexcept;
    [[nodiscard]] static Array<u8> derive(StringRef context, ArrayRef<u8> key_material,
                                          usize out_len = 32u, Allocator* alloc = nullptr);

private:
    struct ChunkState {
        u32 cv[8] = {};
        u64 chunk_counter = 0u;
        u8 buf[64] = {};
        u8 buf_len = 0u;
        u8 blocks_compressed = 0u;
        u8 flags = 0u;
    };

    void init_internal(const u32 key_words[8], u8 flags) noexcept;
    void add_chunk_cv(u32 new_cv[8], u64 total_chunks) noexcept;

    u32 m_key_words[8] = {};
    ChunkState m_chunk = {};
    u32 m_cv_stack[54][8] = {};
    u8 m_cv_stack_len = 0u;
    u8 m_flags = 0u;
};

// Convenience one-shot helpers
[[nodiscard]] StaticArray<u8, 32u> blake2b_256(ArrayRef<u8> data) noexcept;
[[nodiscard]] StaticArray<u8, 64u> blake2b_512(ArrayRef<u8> data) noexcept;
[[nodiscard]] StaticArray<u8, 32u> blake2s_256(ArrayRef<u8> data) noexcept;
[[nodiscard]] inline StaticArray<u8, 32u> blake3(ArrayRef<u8> data) noexcept { return Blake3::hash(data); }
[[nodiscard]] inline StaticArray<u8, 32u> blake3(StringRef data) noexcept { return Blake3::hash(data); }

} // namespace keel::crypto
