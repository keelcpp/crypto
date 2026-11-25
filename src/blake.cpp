#include "keel/crypto/blake.h"

#include "keel/crypto/ct.h"
#include "keel/memory.h"

namespace keel::crypto {

namespace {

constexpr u64 rotr64(u64 x, u32 n) noexcept { return (x >> n) | (x << (64u - n)); }
constexpr u32 rotr32(u32 x, u32 n) noexcept { return (x >> n) | (x << (32u - n)); }

constexpr u32 load_le32(const u8* p) noexcept {
    return as<u32>(p[0]) | (as<u32>(p[1]) << 8u) | (as<u32>(p[2]) << 16u) | (as<u32>(p[3]) << 24u);
}

constexpr void store_le32(u8* p, u32 v) noexcept {
    p[0] = as<u8>(v & 0xFFu);
    p[1] = as<u8>((v >> 8u) & 0xFFu);
    p[2] = as<u8>((v >> 16u) & 0xFFu);
    p[3] = as<u8>((v >> 24u) & 0xFFu);
}

constexpr u64 load_le64(const u8* p) noexcept {
    return as<u64>(p[0]) | (as<u64>(p[1]) << 8u) | (as<u64>(p[2]) << 16u) |
           (as<u64>(p[3]) << 24u) | (as<u64>(p[4]) << 32u) | (as<u64>(p[5]) << 40u) |
           (as<u64>(p[6]) << 48u) | (as<u64>(p[7]) << 56u);
}

constexpr void store_le64(u8* p, u64 v) noexcept {
    for (usize i = 0u; i < 8u; ++i) p[i] = as<u8>((v >> (i * 8u)) & 0xFFu);
}

constexpr u64 kBlake2bIv[8] = {
    0x6a09e667f3bcc908ull, 0xbb67ae8584caa73bull, 0x3c6ef372fe94f82bull, 0xa54ff53a5f1d36f1ull,
    0x510e527fade682d1ull, 0x9b05688c2b3e6c1full, 0x1f83d9abfb41bd6bull, 0x5be0cd19137e2179ull
};

constexpr u32 kBlake2sIv[8] = {
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
};

constexpr u8 kBlake2Sigma[10][16] = {
    {0u, 1u, 2u, 3u, 4u, 5u, 6u, 7u, 8u, 9u, 10u, 11u, 12u, 13u, 14u, 15u},
    {14u, 10u, 4u, 8u, 9u, 15u, 13u, 6u, 1u, 12u, 0u, 2u, 11u, 7u, 5u, 3u},
    {11u, 8u, 12u, 0u, 5u, 2u, 15u, 13u, 10u, 14u, 3u, 6u, 7u, 1u, 9u, 4u},
    {7u, 9u, 3u, 1u, 13u, 12u, 11u, 14u, 2u, 6u, 5u, 10u, 4u, 0u, 15u, 8u},
    {9u, 0u, 5u, 7u, 2u, 4u, 10u, 15u, 14u, 1u, 11u, 12u, 6u, 8u, 3u, 13u},
    {2u, 12u, 6u, 10u, 0u, 11u, 8u, 3u, 4u, 13u, 7u, 5u, 15u, 14u, 1u, 9u},
    {12u, 5u, 1u, 15u, 14u, 13u, 4u, 10u, 0u, 7u, 6u, 3u, 9u, 2u, 8u, 11u},
    {13u, 11u, 7u, 14u, 12u, 1u, 3u, 9u, 5u, 0u, 15u, 4u, 8u, 6u, 2u, 10u},
    {6u, 15u, 14u, 9u, 11u, 3u, 0u, 8u, 12u, 2u, 13u, 7u, 1u, 4u, 10u, 5u},
    {10u, 2u, 8u, 4u, 7u, 6u, 1u, 5u, 15u, 11u, 9u, 14u, 3u, 12u, 13u, 0u}
};

// BLAKE3 domain separation flags
constexpr u8 kB3ChunkStart        = 1u << 0u;
constexpr u8 kB3ChunkEnd          = 1u << 1u;
constexpr u8 kB3Parent            = 1u << 2u;
constexpr u8 kB3Root              = 1u << 3u;
constexpr u8 kB3KeyedHash         = 1u << 4u;
constexpr u8 kB3DeriveKeyContext  = 1u << 5u;
constexpr u8 kB3DeriveKeyMaterial = 1u << 6u;

constexpr u8 kB3MsgPerm[16] = {
    2u, 6u, 3u, 10u, 7u, 0u, 4u, 13u, 1u, 11u, 12u, 5u, 9u, 14u, 15u, 8u
};

inline void b3_g(u32 s[16], usize a, usize b, usize c, usize d, u32 mx, u32 my) noexcept {
    s[a] = s[a] + s[b] + mx;
    s[d] = rotr32(s[d] ^ s[a], 16u);
    s[c] = s[c] + s[d];
    s[b] = rotr32(s[b] ^ s[c], 12u);
    s[a] = s[a] + s[b] + my;
    s[d] = rotr32(s[d] ^ s[a], 8u);
    s[c] = s[c] + s[d];
    s[b] = rotr32(s[b] ^ s[c], 7u);
}

inline void b3_round(u32 s[16], const u32 m[16]) noexcept {
    b3_g(s, 0u, 4u, 8u,  12u, m[0],  m[1]);
    b3_g(s, 1u, 5u, 9u,  13u, m[2],  m[3]);
    b3_g(s, 2u, 6u, 10u, 14u, m[4],  m[5]);
    b3_g(s, 3u, 7u, 11u, 15u, m[6],  m[7]);
    b3_g(s, 0u, 5u, 10u, 15u, m[8],  m[9]);
    b3_g(s, 1u, 6u, 11u, 12u, m[10], m[11]);
    b3_g(s, 2u, 7u, 8u,  13u, m[12], m[13]);
    b3_g(s, 3u, 4u, 9u,  14u, m[14], m[15]);
}

void b3_compress(const u32 cv[8], const u32 block_words[16], u64 counter,
                 u32 block_len, u8 flags, u32 out[16]) noexcept {
    u32 s[16] = {
        cv[0], cv[1], cv[2], cv[3], cv[4], cv[5], cv[6], cv[7],
        kBlake2sIv[0], kBlake2sIv[1], kBlake2sIv[2], kBlake2sIv[3],
        as<u32>(counter & 0xFFFFFFFFu), as<u32>(counter >> 32u), block_len, as<u32>(flags)
    };
    u32 m[16];
    for (usize i = 0u; i < 16u; ++i) m[i] = block_words[i];

    for (usize r = 0u; r < 7u; ++r) {
        b3_round(s, m);
        if (r < 6u) {
            u32 perm[16];
            for (usize i = 0u; i < 16u; ++i) perm[i] = m[kB3MsgPerm[i]];
            for (usize i = 0u; i < 16u; ++i) m[i] = perm[i];
        }
    }
    for (usize i = 0u; i < 8u; ++i) {
        out[i] = s[i] ^ s[i + 8u];
        out[i + 8u] = s[i + 8u] ^ cv[i];
    }
    secure_zero(s, sizeof(s));
    secure_zero(m, sizeof(m));
}

struct B3Output {
    u32 input_cv[8];
    u32 block_words[16];
    u64 counter;
    u32 block_len;
    u8 flags;

    void chaining_value(u32 out_cv[8]) const noexcept {
        u32 full[16];
        b3_compress(input_cv, block_words, counter, block_len, flags, full);
        for (usize i = 0u; i < 8u; ++i) out_cv[i] = full[i];
        secure_zero(full, sizeof(full));
    }

    void root_output_bytes(u8* out, usize out_len, u64 seek) const noexcept {
        u64 block_idx = seek / 64u;
        usize offset_in_block = as<usize>(seek % 64u);
        usize written = 0u;
        u32 words[16];
        u8 block_bytes[64];
        while (written < out_len) {
            b3_compress(input_cv, block_words, block_idx, block_len, as<u8>(flags | kB3Root), words);
            for (usize i = 0u; i < 16u; ++i) store_le32(block_bytes + i * 4u, words[i]);
            const usize avail = 64u - offset_in_block;
            const usize take = (out_len - written < avail) ? (out_len - written) : avail;
            mem_copy(out + written, block_bytes + offset_in_block, take);
            written += take;
            offset_in_block = 0u;
            ++block_idx;
        }
        secure_zero(words, sizeof(words));
        secure_zero(block_bytes, sizeof(block_bytes));
    }
};

B3Output b3_parent_output(const u32 left_cv[8], const u32 right_cv[8],
                          const u32 key_words[8], u8 flags) noexcept {
    B3Output o{};
    for (usize i = 0u; i < 8u; ++i) {
        o.input_cv[i] = key_words[i];
        o.block_words[i] = left_cv[i];
        o.block_words[i + 8u] = right_cv[i];
    }
    o.counter = 0u;
    o.block_len = 64u;
    o.flags = as<u8>(flags | kB3Parent);
    return o;
}

} // namespace

// ---------------------------------------------------------------------------
// BLAKE2b
// ---------------------------------------------------------------------------
Blake2b::Blake2b(usize out_len, ArrayRef<u8> key) noexcept {
    (void)init(out_len, key);
}

Blake2b::~Blake2b() noexcept {
    secure_zero(m_h, sizeof(m_h));
    secure_zero(m_t, sizeof(m_t));
    secure_zero(m_buf, sizeof(m_buf));
    m_buf_len = 0u;
}

bool Blake2b::init(usize out_len, ArrayRef<u8> key) noexcept {
    if (out_len == 0u || out_len > kMaxDigestSize || key.size() > kMaxKeySize) {
        secure_zero(m_h, sizeof(m_h));
        secure_zero(m_t, sizeof(m_t));
        secure_zero(m_buf, sizeof(m_buf));
        m_buf_len = 0u;
        m_out_len = 0u;
        return false;
    }
    for (usize i = 0u; i < 8u; ++i) m_h[i] = kBlake2bIv[i];
    m_h[0] ^= 0x01010000ull ^ (as<u64>(key.size()) << 8u) ^ as<u64>(out_len);
    m_t[0] = 0u;
    m_t[1] = 0u;
    m_buf_len = 0u;
    m_out_len = out_len;
    if (!key.empty()) {
        mem_zero(m_buf, kBlockSize);
        mem_copy(m_buf, key.data(), key.size());
        m_buf_len = kBlockSize;
    }
    return true;
}

void Blake2b::compress(const u8 block[128], bool is_last) noexcept {
    u64 v[16];
    u64 m[16];
    for (usize i = 0u; i < 8u; ++i) {
        v[i] = m_h[i];
        v[i + 8u] = kBlake2bIv[i];
    }
    v[12] ^= m_t[0];
    v[13] ^= m_t[1];
    if (is_last) v[14] = ~v[14];

    for (usize i = 0u; i < 16u; ++i) m[i] = load_le64(block + i * 8u);

    auto g = [&](usize a, usize b, usize c, usize d, u64 x, u64 y) {
        v[a] = v[a] + v[b] + x;
        v[d] = rotr64(v[d] ^ v[a], 32u);
        v[c] = v[c] + v[d];
        v[b] = rotr64(v[b] ^ v[c], 24u);
        v[a] = v[a] + v[b] + y;
        v[d] = rotr64(v[d] ^ v[a], 16u);
        v[c] = v[c] + v[d];
        v[b] = rotr64(v[b] ^ v[c], 63u);
    };

    for (usize r = 0u; r < 12u; ++r) {
        const u8* s = kBlake2Sigma[r % 10u];
        g(0u, 4u, 8u,  12u, m[s[0]],  m[s[1]]);
        g(1u, 5u, 9u,  13u, m[s[2]],  m[s[3]]);
        g(2u, 6u, 10u, 14u, m[s[4]],  m[s[5]]);
        g(3u, 7u, 11u, 15u, m[s[6]],  m[s[7]]);
        g(0u, 5u, 10u, 15u, m[s[8]],  m[s[9]]);
        g(1u, 6u, 11u, 12u, m[s[10]], m[s[11]]);
        g(2u, 7u, 8u,  13u, m[s[12]], m[s[13]]);
        g(3u, 4u, 9u,  14u, m[s[14]], m[s[15]]);
    }
    for (usize i = 0u; i < 8u; ++i) m_h[i] ^= v[i] ^ v[i + 8u];
    secure_zero(v, sizeof(v));
    secure_zero(m, sizeof(m));
}

void Blake2b::update(const u8* data, usize len) noexcept {
    if (m_out_len == 0u || len == 0u || !data) return;
    for (usize i = 0u; i < len; ++i) {
        if (m_buf_len == kBlockSize) {
            m_t[0] += as<u64>(kBlockSize);
            if (m_t[0] < as<u64>(kBlockSize)) ++m_t[1];
            compress(m_buf, false);
            m_buf_len = 0u;
        }
        m_buf[m_buf_len++] = data[i];
    }
}

void Blake2b::finalize(u8* out) noexcept {
    if (m_out_len == 0u || !out) return;
    m_t[0] += as<u64>(m_buf_len);
    if (m_t[0] < as<u64>(m_buf_len)) ++m_t[1];
    while (m_buf_len < kBlockSize) m_buf[m_buf_len++] = 0u;
    compress(m_buf, true);

    u8 full[64];
    for (usize i = 0u; i < 8u; ++i) store_le64(full + i * 8u, m_h[i]);
    mem_copy(out, full, m_out_len);
    secure_zero(full, sizeof(full));
    (void)init(m_out_len);
}

Array<u8> Blake2b::finalize(Allocator* alloc) {
    if (m_out_len == 0u) return Array<u8>(alloc);
    Array<u8> out(m_out_len, u8{0u}, alloc);
    finalize(out.data());
    return out;
}

Array<u8> Blake2b::hash(ArrayRef<u8> data, usize out_len, ArrayRef<u8> key, Allocator* alloc) {
    Blake2b ctx;
    if (!ctx.init(out_len, key)) return Array<u8>(alloc);
    ctx.update(data);
    return ctx.finalize(alloc);
}

// ---------------------------------------------------------------------------
// BLAKE2s
// ---------------------------------------------------------------------------
Blake2s::Blake2s(usize out_len, ArrayRef<u8> key) noexcept {
    (void)init(out_len, key);
}

Blake2s::~Blake2s() noexcept {
    secure_zero(m_h, sizeof(m_h));
    secure_zero(m_t, sizeof(m_t));
    secure_zero(m_buf, sizeof(m_buf));
    m_buf_len = 0u;
}

bool Blake2s::init(usize out_len, ArrayRef<u8> key) noexcept {
    if (out_len == 0u || out_len > kMaxDigestSize || key.size() > kMaxKeySize) {
        secure_zero(m_h, sizeof(m_h));
        secure_zero(m_t, sizeof(m_t));
        secure_zero(m_buf, sizeof(m_buf));
        m_buf_len = 0u;
        m_out_len = 0u;
        return false;
    }
    for (usize i = 0u; i < 8u; ++i) m_h[i] = kBlake2sIv[i];
    m_h[0] ^= 0x01010000u ^ (as<u32>(key.size()) << 8u) ^ as<u32>(out_len);
    m_t[0] = 0u;
    m_t[1] = 0u;
    m_buf_len = 0u;
    m_out_len = out_len;
    if (!key.empty()) {
        mem_zero(m_buf, kBlockSize);
        mem_copy(m_buf, key.data(), key.size());
        m_buf_len = kBlockSize;
    }
    return true;
}

void Blake2s::compress(const u8 block[64], bool is_last) noexcept {
    u32 v[16];
    u32 m[16];
    for (usize i = 0u; i < 8u; ++i) {
        v[i] = m_h[i];
        v[i + 8u] = kBlake2sIv[i];
    }
    v[12] ^= m_t[0];
    v[13] ^= m_t[1];
    if (is_last) v[14] = ~v[14];

    for (usize i = 0u; i < 16u; ++i) m[i] = load_le32(block + i * 4u);

    auto g = [&](usize a, usize b, usize c, usize d, u32 x, u32 y) {
        v[a] = v[a] + v[b] + x;
        v[d] = rotr32(v[d] ^ v[a], 16u);
        v[c] = v[c] + v[d];
        v[b] = rotr32(v[b] ^ v[c], 12u);
        v[a] = v[a] + v[b] + y;
        v[d] = rotr32(v[d] ^ v[a], 8u);
        v[c] = v[c] + v[d];
        v[b] = rotr32(v[b] ^ v[c], 7u);
    };

    for (usize r = 0u; r < 10u; ++r) {
        const u8* s = kBlake2Sigma[r];
        g(0u, 4u, 8u,  12u, m[s[0]],  m[s[1]]);
        g(1u, 5u, 9u,  13u, m[s[2]],  m[s[3]]);
        g(2u, 6u, 10u, 14u, m[s[4]],  m[s[5]]);
        g(3u, 7u, 11u, 15u, m[s[6]],  m[s[7]]);
        g(0u, 5u, 10u, 15u, m[s[8]],  m[s[9]]);
        g(1u, 6u, 11u, 12u, m[s[10]], m[s[11]]);
        g(2u, 7u, 8u,  13u, m[s[12]], m[s[13]]);
        g(3u, 4u, 9u,  14u, m[s[14]], m[s[15]]);
    }
    for (usize i = 0u; i < 8u; ++i) m_h[i] ^= v[i] ^ v[i + 8u];
    secure_zero(v, sizeof(v));
    secure_zero(m, sizeof(m));
}

void Blake2s::update(const u8* data, usize len) noexcept {
    if (m_out_len == 0u || len == 0u || !data) return;
    for (usize i = 0u; i < len; ++i) {
        if (m_buf_len == kBlockSize) {
            m_t[0] += as<u32>(kBlockSize);
            if (m_t[0] < as<u32>(kBlockSize)) ++m_t[1];
            compress(m_buf, false);
            m_buf_len = 0u;
        }
        m_buf[m_buf_len++] = data[i];
    }
}

void Blake2s::finalize(u8* out) noexcept {
    if (m_out_len == 0u || !out) return;
    m_t[0] += as<u32>(m_buf_len);
    if (m_t[0] < as<u32>(m_buf_len)) ++m_t[1];
    while (m_buf_len < kBlockSize) m_buf[m_buf_len++] = 0u;
    compress(m_buf, true);

    u8 full[32];
    for (usize i = 0u; i < 8u; ++i) store_le32(full + i * 4u, m_h[i]);
    mem_copy(out, full, m_out_len);
    secure_zero(full, sizeof(full));
    (void)init(m_out_len);
}

Array<u8> Blake2s::finalize(Allocator* alloc) {
    if (m_out_len == 0u) return Array<u8>(alloc);
    Array<u8> out(m_out_len, u8{0u}, alloc);
    finalize(out.data());
    return out;
}

Array<u8> Blake2s::hash(ArrayRef<u8> data, usize out_len, ArrayRef<u8> key, Allocator* alloc) {
    Blake2s ctx;
    if (!ctx.init(out_len, key)) return Array<u8>(alloc);
    ctx.update(data);
    return ctx.finalize(alloc);
}

// ---------------------------------------------------------------------------
// BLAKE3
// ---------------------------------------------------------------------------
void Blake3::init_internal(const u32 key_words[8], u8 flags) noexcept {
    for (usize i = 0u; i < 8u; ++i) {
        m_key_words[i] = key_words[i];
        m_chunk.cv[i] = key_words[i];
    }
    m_chunk.chunk_counter = 0u;
    mem_zero(m_chunk.buf, sizeof(m_chunk.buf));
    m_chunk.buf_len = 0u;
    m_chunk.blocks_compressed = 0u;
    m_chunk.flags = flags;
    m_cv_stack_len = 0u;
    m_flags = flags;
}

Blake3::Blake3() noexcept {
    init_internal(kBlake2sIv, 0u);
}

Blake3::~Blake3() noexcept {
    secure_zero(m_key_words, sizeof(m_key_words));
    secure_zero(&m_chunk, sizeof(m_chunk));
    secure_zero(m_cv_stack, sizeof(m_cv_stack));
    m_cv_stack_len = 0u;
}

Blake3 Blake3::keyed(const u8 key[32]) noexcept {
    u32 kw[8] = {};
    if (key) {
        for (usize i = 0u; i < 8u; ++i) kw[i] = load_le32(key + i * 4u);
    }
    Blake3 h;
    h.init_internal(kw, kB3KeyedHash);
    secure_zero(kw, sizeof(kw));
    return h;
}

Blake3 Blake3::derive_key(StringRef context) noexcept {
    Blake3 ctx_hasher;
    ctx_hasher.init_internal(kBlake2sIv, kB3DeriveKeyContext);
    ctx_hasher.update(context);
    u8 ctx_key[32];
    ctx_hasher.finalize(ctx_key, 32u);
    u32 kw[8];
    for (usize i = 0u; i < 8u; ++i) kw[i] = load_le32(ctx_key + i * 4u);
    Blake3 h;
    h.init_internal(kw, kB3DeriveKeyMaterial);
    secure_zero(ctx_key, sizeof(ctx_key));
    secure_zero(kw, sizeof(kw));
    return h;
}

void Blake3::reset() noexcept {
    u32 kw[8];
    for (usize i = 0u; i < 8u; ++i) kw[i] = m_key_words[i];
    init_internal(kw, m_flags);
    secure_zero(kw, sizeof(kw));
}

void Blake3::add_chunk_cv(u32 new_cv[8], u64 total_chunks) noexcept {
    while ((total_chunks & 1u) == 0u) {
        --m_cv_stack_len;
        const B3Output parent = b3_parent_output(m_cv_stack[m_cv_stack_len], new_cv, m_key_words, m_flags);
        parent.chaining_value(new_cv);
        total_chunks >>= 1u;
    }
    for (usize i = 0u; i < 8u; ++i) m_cv_stack[m_cv_stack_len][i] = new_cv[i];
    ++m_cv_stack_len;
}

void Blake3::update(const u8* data, usize len) noexcept {
    if (len == 0u || !data) return;
    usize off = 0u;
    while (off < len) {
        const usize chunk_len = as<usize>(m_chunk.blocks_compressed) * 64u + as<usize>(m_chunk.buf_len);
        if (chunk_len == kChunkSize) {
            // Finalize current 1024-byte chunk.
            u32 words[16];
            for (usize i = 0u; i < 16u; ++i) words[i] = load_le32(m_chunk.buf + i * 4u);
            const u8 start_flag = (m_chunk.blocks_compressed == 0u) ? kB3ChunkStart : 0u;
            B3Output o{};
            for (usize i = 0u; i < 8u; ++i) o.input_cv[i] = m_chunk.cv[i];
            for (usize i = 0u; i < 16u; ++i) o.block_words[i] = words[i];
            o.counter = m_chunk.chunk_counter;
            o.block_len = as<u32>(m_chunk.buf_len);
            o.flags = as<u8>(m_chunk.flags | start_flag | kB3ChunkEnd);
            u32 chunk_cv[8];
            o.chaining_value(chunk_cv);
            const u64 total_chunks = m_chunk.chunk_counter + 1u;
            add_chunk_cv(chunk_cv, total_chunks);
            secure_zero(words, sizeof(words));
            secure_zero(&o, sizeof(o));
            secure_zero(chunk_cv, sizeof(chunk_cv));

            for (usize i = 0u; i < 8u; ++i) m_chunk.cv[i] = m_key_words[i];
            m_chunk.chunk_counter = total_chunks;
            mem_zero(m_chunk.buf, sizeof(m_chunk.buf));
            m_chunk.buf_len = 0u;
            m_chunk.blocks_compressed = 0u;
        }

        if (m_chunk.buf_len == 64u) {
            u32 words[16];
            for (usize i = 0u; i < 16u; ++i) words[i] = load_le32(m_chunk.buf + i * 4u);
            const u8 start_flag = (m_chunk.blocks_compressed == 0u) ? kB3ChunkStart : 0u;
            u32 out16[16];
            b3_compress(m_chunk.cv, words, m_chunk.chunk_counter, 64u,
                        as<u8>(m_chunk.flags | start_flag), out16);
            for (usize i = 0u; i < 8u; ++i) m_chunk.cv[i] = out16[i];
            secure_zero(words, sizeof(words));
            secure_zero(out16, sizeof(out16));
            ++m_chunk.blocks_compressed;
            mem_zero(m_chunk.buf, sizeof(m_chunk.buf));
            m_chunk.buf_len = 0u;
        }

        const usize want = 64u - as<usize>(m_chunk.buf_len);
        const usize take = (len - off < want) ? (len - off) : want;
        mem_copy(m_chunk.buf + m_chunk.buf_len, data + off, take);
        m_chunk.buf_len = as<u8>(m_chunk.buf_len + take);
        off += take;
    }
}

void Blake3::finalize(u8* out, usize out_len, u64 seek) const noexcept {
    if (out_len == 0u || !out) return;
    u8 padded[64] = {};
    if (m_chunk.buf_len > 0u) mem_copy(padded, m_chunk.buf, m_chunk.buf_len);
    B3Output output{};
    for (usize i = 0u; i < 8u; ++i) output.input_cv[i] = m_chunk.cv[i];
    for (usize i = 0u; i < 16u; ++i) output.block_words[i] = load_le32(padded + i * 4u);
    output.counter = m_chunk.chunk_counter;
    output.block_len = as<u32>(m_chunk.buf_len);
    const u8 start_flag = (m_chunk.blocks_compressed == 0u) ? kB3ChunkStart : 0u;
    output.flags = as<u8>(m_chunk.flags | start_flag | kB3ChunkEnd);

    usize remaining = as<usize>(m_cv_stack_len);
    u32 right_cv[8] = {};
    while (remaining > 0u) {
        --remaining;
        output.chaining_value(right_cv);
        output = b3_parent_output(m_cv_stack[remaining], right_cv, m_key_words, m_flags);
    }
    output.root_output_bytes(out, out_len, seek);
    secure_zero(right_cv, sizeof(right_cv));
    secure_zero(&output, sizeof(output));
    secure_zero(padded, sizeof(padded));
}

StaticArray<u8, 32u> Blake3::finalize() const noexcept {
    StaticArray<u8, 32u> out{};
    finalize(out.data(), 32u, 0u);
    return out;
}

Array<u8> Blake3::finalize_xof(usize out_len, u64 seek, Allocator* alloc) const {
    Array<u8> out(out_len, u8{0u}, alloc);
    finalize(out.data(), out_len, seek);
    return out;
}

StaticArray<u8, 32u> Blake3::hash(ArrayRef<u8> data) noexcept {
    Blake3 h;
    h.update(data);
    return h.finalize();
}

StaticArray<u8, 32u> Blake3::keyed_hash(const u8 key[32], ArrayRef<u8> data) noexcept {
    Blake3 h = Blake3::keyed(key);
    h.update(data);
    return h.finalize();
}

Array<u8> Blake3::derive(StringRef context, ArrayRef<u8> key_material,
                         usize out_len, Allocator* alloc) {
    Blake3 h = Blake3::derive_key(context);
    h.update(key_material);
    return h.finalize_xof(out_len, 0u, alloc);
}

StaticArray<u8, 32u> blake2b_256(ArrayRef<u8> data) noexcept {
    StaticArray<u8, 32u> out{};
    Blake2b ctx(32u);
    ctx.update(data);
    ctx.finalize(out.data());
    return out;
}

StaticArray<u8, 64u> blake2b_512(ArrayRef<u8> data) noexcept {
    StaticArray<u8, 64u> out{};
    Blake2b ctx(64u);
    ctx.update(data);
    ctx.finalize(out.data());
    return out;
}

StaticArray<u8, 32u> blake2s_256(ArrayRef<u8> data) noexcept {
    StaticArray<u8, 32u> out{};
    Blake2s ctx(32u);
    ctx.update(data);
    ctx.finalize(out.data());
    return out;
}

} // namespace keel::crypto
