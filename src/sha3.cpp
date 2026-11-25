#include "keel/crypto/sha3.h"

#include "keel/crypto/ct.h"

namespace keel::crypto {

namespace {

constexpr u64 kKeccakRC[24] = {
    0x0000000000000001ull, 0x0000000000008082ull, 0x800000000000808aull, 0x8000000080008000ull,
    0x000000000000808bull, 0x0000000080000001ull, 0x8000000080008081ull, 0x8000000000008009ull,
    0x000000000000008aull, 0x0000000000000088ull, 0x0000000080008009ull, 0x000000008000000aull,
    0x000000008000808bull, 0x800000000000008bull, 0x8000000000008089ull, 0x8000000000008003ull,
    0x8000000000008002ull, 0x8000000000000080ull, 0x000000000000800aull, 0x800000008000000aull,
    0x8000000080008081ull, 0x8000000000008080ull, 0x0000000080000001ull, 0x8000000080008008ull
};

constexpr u32 kKeccakRot[24] = {
    1u,  3u,  6u,  10u, 15u, 21u, 28u, 36u, 45u, 55u, 2u,  14u,
    27u, 41u, 56u, 8u,  25u, 43u, 62u, 18u, 39u, 61u, 20u, 44u
};

constexpr usize kKeccakPi[24] = {
    10u, 7u,  11u, 17u, 18u, 3u, 5u,  16u, 8u,  21u, 24u, 4u,
    15u, 23u, 19u, 13u, 12u, 2u, 20u, 14u, 22u, 9u,  6u,  1u
};

constexpr u64 rotl64(u64 x, u32 n) noexcept {
    return (x << n) | (x >> (64u - n));
}

} // namespace

namespace detail {

KeccakSponge::~KeccakSponge() noexcept {
    secure_zero(m_state, sizeof(m_state));
    m_pos = 0u;
    m_squeezing = false;
}

void KeccakSponge::reset(usize rate_bytes, u8 domain_pad) noexcept {
    for (usize i = 0u; i < 25u; ++i) m_state[i] = 0u;
    m_rate = rate_bytes;
    m_pos = 0u;
    m_pad = domain_pad;
    m_squeezing = false;
}

void KeccakSponge::permute() noexcept {
    u64 bc[5];
    for (usize round = 0u; round < 24u; ++round) {
        // Theta
        for (usize i = 0u; i < 5u; ++i) {
            bc[i] = m_state[i] ^ m_state[i + 5u] ^ m_state[i + 10u] ^ m_state[i + 15u] ^ m_state[i + 20u];
        }
        for (usize i = 0u; i < 5u; ++i) {
            const u64 t = bc[(i + 4u) % 5u] ^ rotl64(bc[(i + 1u) % 5u], 1u);
            for (usize j = 0u; j < 25u; j += 5u) {
                m_state[j + i] ^= t;
            }
        }
        // Rho + Pi
        u64 t = m_state[1];
        for (usize i = 0u; i < 24u; ++i) {
            const usize j = kKeccakPi[i];
            bc[0] = m_state[j];
            m_state[j] = rotl64(t, kKeccakRot[i]);
            t = bc[0];
        }
        // Chi
        for (usize j = 0u; j < 25u; j += 5u) {
            for (usize i = 0u; i < 5u; ++i) bc[i] = m_state[j + i];
            for (usize i = 0u; i < 5u; ++i) {
                m_state[j + i] ^= (~bc[(i + 1u) % 5u]) & bc[(i + 2u) % 5u];
            }
        }
        // Iota
        m_state[0] ^= kKeccakRC[round];
    }
    secure_zero(bc, sizeof(bc));
}

void KeccakSponge::absorb(const u8* data, usize len) noexcept {
    if (len == 0u || !data) return;
    if (m_squeezing) reset(m_rate, m_pad);
    for (usize i = 0u; i < len; ++i) {
        const usize lane = m_pos >> 3u;
        const u32 shift = as<u32>((m_pos & 7u) * 8u);
        m_state[lane] ^= as<u64>(data[i]) << shift;
        ++m_pos;
        if (m_pos == m_rate) {
            permute();
            m_pos = 0u;
        }
    }
}

void KeccakSponge::finalize_absorb() noexcept {
    if (m_squeezing) return;
    // Pad10*1 with domain separation suffix m_pad
    m_state[m_pos >> 3u] ^= as<u64>(m_pad) << as<u32>((m_pos & 7u) * 8u);
    const usize last = m_rate - 1u;
    m_state[last >> 3u] ^= u64{0x80u} << as<u32>((last & 7u) * 8u);
    permute();
    m_pos = 0u;
    m_squeezing = true;
}

void KeccakSponge::squeeze(u8* out, usize len) noexcept {
    if (len == 0u || !out) return;
    if (!m_squeezing) finalize_absorb();
    for (usize i = 0u; i < len; ++i) {
        if (m_pos == m_rate) {
            permute();
            m_pos = 0u;
        }
        const usize lane = m_pos >> 3u;
        const u32 shift = as<u32>((m_pos & 7u) * 8u);
        out[i] = as<u8>((m_state[lane] >> shift) & 0xFFu);
        ++m_pos;
    }
}

} // namespace detail

void Sha3_224::finalize(u8* out) noexcept {
    if (out) m_sponge.squeeze(out, kDigestSize);
    reset();
}

StaticArray<u8, Sha3_224::kDigestSize> Sha3_224::finalize() noexcept {
    StaticArray<u8, kDigestSize> out{};
    finalize(out.data());
    return out;
}

StaticArray<u8, Sha3_224::kDigestSize> Sha3_224::hash(ArrayRef<u8> data) noexcept {
    Sha3_224 ctx;
    ctx.update(data);
    return ctx.finalize();
}

void Sha3_256::finalize(u8* out) noexcept {
    if (out) m_sponge.squeeze(out, kDigestSize);
    reset();
}

StaticArray<u8, Sha3_256::kDigestSize> Sha3_256::finalize() noexcept {
    StaticArray<u8, kDigestSize> out{};
    finalize(out.data());
    return out;
}

StaticArray<u8, Sha3_256::kDigestSize> Sha3_256::hash(ArrayRef<u8> data) noexcept {
    Sha3_256 ctx;
    ctx.update(data);
    return ctx.finalize();
}

void Sha3_384::finalize(u8* out) noexcept {
    if (out) m_sponge.squeeze(out, kDigestSize);
    reset();
}

StaticArray<u8, Sha3_384::kDigestSize> Sha3_384::finalize() noexcept {
    StaticArray<u8, kDigestSize> out{};
    finalize(out.data());
    return out;
}

StaticArray<u8, Sha3_384::kDigestSize> Sha3_384::hash(ArrayRef<u8> data) noexcept {
    Sha3_384 ctx;
    ctx.update(data);
    return ctx.finalize();
}

void Sha3_512::finalize(u8* out) noexcept {
    if (out) m_sponge.squeeze(out, kDigestSize);
    reset();
}

StaticArray<u8, Sha3_512::kDigestSize> Sha3_512::finalize() noexcept {
    StaticArray<u8, kDigestSize> out{};
    finalize(out.data());
    return out;
}

StaticArray<u8, Sha3_512::kDigestSize> Sha3_512::hash(ArrayRef<u8> data) noexcept {
    Sha3_512 ctx;
    ctx.update(data);
    return ctx.finalize();
}

Array<u8> Shake128::xof(ArrayRef<u8> data, usize out_len, Allocator* alloc) {
    Array<u8> out(out_len, u8{0u}, alloc);
    Shake128 ctx;
    ctx.update(data);
    ctx.squeeze(out.data(), out_len);
    return out;
}

Array<u8> Shake256::xof(ArrayRef<u8> data, usize out_len, Allocator* alloc) {
    Array<u8> out(out_len, u8{0u}, alloc);
    Shake256 ctx;
    ctx.update(data);
    ctx.squeeze(out.data(), out_len);
    return out;
}

} // namespace keel::crypto
