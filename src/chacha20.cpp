#include "keel/crypto/chacha20.h"

#include "keel/crypto/ct.h"
#include "keel/memory.h"

namespace keel::crypto {

namespace {

[[nodiscard]] constexpr u32 load_le32(const u8* p) noexcept {
    return as<u32>(p[0]) | (as<u32>(p[1]) << 8u) | (as<u32>(p[2]) << 16u) | (as<u32>(p[3]) << 24u);
}

constexpr void store_le32(u8* p, u32 v) noexcept {
    p[0] = as<u8>(v & 0xFFu);
    p[1] = as<u8>((v >> 8u) & 0xFFu);
    p[2] = as<u8>((v >> 16u) & 0xFFu);
    p[3] = as<u8>((v >> 24u) & 0xFFu);
}

constexpr void store_le64(u8* p, u64 v) noexcept {
    for (usize i = 0u; i < 8u; ++i) p[i] = as<u8>((v >> (8u * i)) & 0xFFu);
}

[[nodiscard]] constexpr u32 rotl32(u32 v, u32 n) noexcept {
    return (v << n) | (v >> (32u - n));
}

constexpr void quarter_round(u32& a, u32& b, u32& c, u32& d) noexcept {
    a += b;
    d ^= a;
    d = rotl32(d, 16u);
    c += d;
    b ^= c;
    b = rotl32(b, 12u);
    a += b;
    d ^= a;
    d = rotl32(d, 8u);
    c += d;
    b ^= c;
    b = rotl32(b, 7u);
}

void chacha20_core(u32 state[16]) noexcept {
    for (u32 i = 0u; i < 10u; ++i) {
        quarter_round(state[0], state[4], state[8], state[12]);
        quarter_round(state[1], state[5], state[9], state[13]);
        quarter_round(state[2], state[6], state[10], state[14]);
        quarter_round(state[3], state[7], state[11], state[15]);
        quarter_round(state[0], state[5], state[10], state[15]);
        quarter_round(state[1], state[6], state[11], state[12]);
        quarter_round(state[2], state[7], state[8], state[13]);
        quarter_round(state[3], state[4], state[9], state[14]);
    }
}

void poly1305_pad16(Poly1305& poly, usize len) noexcept {
    const usize rem = len % 16u;
    if (rem != 0u) {
        static constexpr u8 kZeros[16] = {};
        poly.update(kZeros, 16u - rem);
    }
}

void compute_aead_tag(const u8 key[32], const u8 nonce[12], ArrayRef<u8> aad,
                      ArrayRef<u8> ciphertext, u8 tag_out[16]) noexcept {
    u8 otk_block[64];
    chacha20_block(key, 0u, nonce, otk_block);

    Poly1305 poly(otk_block);
    poly.update(aad);
    poly1305_pad16(poly, aad.size());
    poly.update(ciphertext);
    poly1305_pad16(poly, ciphertext.size());

    u8 lens[16];
    store_le64(lens, as<u64>(aad.size()));
    store_le64(lens + 8u, as<u64>(ciphertext.size()));
    poly.update(lens, 16u);
    poly.finalize(tag_out);

    secure_zero(otk_block, sizeof(otk_block));
}

} // namespace

void chacha20_block(const u8 key[32], u32 counter, const u8 nonce[12], u8 out[64]) noexcept {
    u32 init[16] = {
        0x61707865u, 0x3320646Eu, 0x79622D32u, 0x6B206574u,
        load_le32(key + 0u),  load_le32(key + 4u),  load_le32(key + 8u),  load_le32(key + 12u),
        load_le32(key + 16u), load_le32(key + 20u), load_le32(key + 24u), load_le32(key + 28u),
        counter,
        load_le32(nonce + 0u), load_le32(nonce + 4u), load_le32(nonce + 8u),
    };
    u32 work[16];
    mem_copy(work, init, sizeof(init));
    chacha20_core(work);
    for (usize i = 0u; i < 16u; ++i) store_le32(out + 4u * i, work[i] + init[i]);
    secure_zero(init, sizeof(init));
    secure_zero(work, sizeof(work));
}

bool chacha20_xor(const u8 key[32], u32 counter, const u8 nonce[12],
                  ArrayRef<u8> in, MutArrayRef<u8> out) noexcept {
    if (in.size() != out.size()) return false;
    u8 ks[64];
    usize off = 0u;
    u32 ctr = counter;
    while (off < in.size()) {
        chacha20_block(key, ctr, nonce, ks);
        ++ctr;
        const usize n = (in.size() - off < 64u) ? (in.size() - off) : 64u;
        for (usize i = 0u; i < n; ++i) out[off + i] = as<u8>(in[off + i] ^ ks[i]);
        off += n;
    }
    secure_zero(ks, sizeof(ks));
    return true;
}

void hchacha20(const u8 key[32], const u8 nonce[16], u8 out[32]) noexcept {
    u32 state[16] = {
        0x61707865u, 0x3320646Eu, 0x79622D32u, 0x6B206574u,
        load_le32(key + 0u),   load_le32(key + 4u),   load_le32(key + 8u),   load_le32(key + 12u),
        load_le32(key + 16u),  load_le32(key + 20u),  load_le32(key + 24u),  load_le32(key + 28u),
        load_le32(nonce + 0u), load_le32(nonce + 4u), load_le32(nonce + 8u), load_le32(nonce + 12u),
    };
    chacha20_core(state);
    store_le32(out + 0u, state[0]);
    store_le32(out + 4u, state[1]);
    store_le32(out + 8u, state[2]);
    store_le32(out + 12u, state[3]);
    store_le32(out + 16u, state[12]);
    store_le32(out + 20u, state[13]);
    store_le32(out + 24u, state[14]);
    store_le32(out + 28u, state[15]);
    secure_zero(state, sizeof(state));
}

Poly1305::~Poly1305() noexcept {
    secure_zero(m_r, sizeof(m_r));
    secure_zero(m_h, sizeof(m_h));
    secure_zero(m_pad, sizeof(m_pad));
    secure_zero(m_buf, sizeof(m_buf));
    m_buf_len = 0u;
}

void Poly1305::init(const u8 key[32]) noexcept {
    // Clamp r per RFC 8439 §2.5 and split into five 26-bit limbs.
    m_r[0] = load_le32(key + 0u) & 0x03FFFFFFu;
    m_r[1] = (load_le32(key + 3u) >> 2u) & 0x03FFFF03u;
    m_r[2] = (load_le32(key + 6u) >> 4u) & 0x03FFC0FFu;
    m_r[3] = (load_le32(key + 9u) >> 6u) & 0x03F03FFFu;
    m_r[4] = (load_le32(key + 12u) >> 8u) & 0x000FFFFFu;

    for (usize i = 0u; i < 5u; ++i) m_h[i] = 0u;
    m_pad[0] = load_le32(key + 16u);
    m_pad[1] = load_le32(key + 20u);
    m_pad[2] = load_le32(key + 24u);
    m_pad[3] = load_le32(key + 28u);
    mem_zero(m_buf, sizeof(m_buf));
    m_buf_len = 0u;
}

void Poly1305::process_block(const u8 block[16], bool is_final, usize len) noexcept {
    const u32 r0 = m_r[0];
    const u32 r1 = m_r[1];
    const u32 r2 = m_r[2];
    const u32 r3 = m_r[3];
    const u32 r4 = m_r[4];

    const u32 s1 = r1 * 5u;
    const u32 s2 = r2 * 5u;
    const u32 s3 = r3 * 5u;
    const u32 s4 = r4 * 5u;

    u8 tmp[17] = {};
    mem_copy(tmp, block, len);
    if (!is_final || len > 0u) tmp[len] = 1u;

    u32 h0 = m_h[0] + (load_le32(tmp + 0u) & 0x03FFFFFFu);
    u32 h1 = m_h[1] + ((load_le32(tmp + 3u) >> 2u) & 0x03FFFFFFu);
    u32 h2 = m_h[2] + ((load_le32(tmp + 6u) >> 4u) & 0x03FFFFFFu);
    u32 h3 = m_h[3] + ((load_le32(tmp + 9u) >> 6u) & 0x03FFFFFFu);
    u32 h4 = m_h[4] + ((load_le32(tmp + 12u) >> 8u) | (as<u32>(tmp[16]) << 24u));

    const u64 d0 = as<u64>(h0) * r0 + as<u64>(h1) * s4 + as<u64>(h2) * s3 +
                   as<u64>(h3) * s2 + as<u64>(h4) * s1;
    u64 d1 = as<u64>(h0) * r1 + as<u64>(h1) * r0 + as<u64>(h2) * s4 +
             as<u64>(h3) * s3 + as<u64>(h4) * s2;
    u64 d2 = as<u64>(h0) * r2 + as<u64>(h1) * r1 + as<u64>(h2) * r0 +
             as<u64>(h3) * s4 + as<u64>(h4) * s3;
    u64 d3 = as<u64>(h0) * r3 + as<u64>(h1) * r2 + as<u64>(h2) * r1 +
             as<u64>(h3) * r0 + as<u64>(h4) * s4;
    u64 d4 = as<u64>(h0) * r4 + as<u64>(h1) * r3 + as<u64>(h2) * r2 +
             as<u64>(h3) * r1 + as<u64>(h4) * r0;

    u32 c = as<u32>(d0 >> 26u);
    h0 = as<u32>(d0) & 0x03FFFFFFu;
    d1 += c;
    c = as<u32>(d1 >> 26u);
    h1 = as<u32>(d1) & 0x03FFFFFFu;
    d2 += c;
    c = as<u32>(d2 >> 26u);
    h2 = as<u32>(d2) & 0x03FFFFFFu;
    d3 += c;
    c = as<u32>(d3 >> 26u);
    h3 = as<u32>(d3) & 0x03FFFFFFu;
    d4 += c;
    c = as<u32>(d4 >> 26u);
    h4 = as<u32>(d4) & 0x03FFFFFFu;
    h0 += c * 5u;
    c = h0 >> 26u;
    h0 &= 0x03FFFFFFu;
    h1 += c;

    m_h[0] = h0;
    m_h[1] = h1;
    m_h[2] = h2;
    m_h[3] = h3;
    m_h[4] = h4;
    secure_zero(tmp, sizeof(tmp));
}

void Poly1305::update(const u8* data, usize len) noexcept {
    if (len == 0u || data == nullptr) return;
    usize off = 0u;
    if (m_buf_len > 0u) {
        const usize take = (16u - m_buf_len < len) ? (16u - m_buf_len) : len;
        mem_copy(m_buf + m_buf_len, data, take);
        m_buf_len += take;
        off += take;
        if (m_buf_len == 16u) {
            process_block(m_buf, false, 16u);
            m_buf_len = 0u;
        }
    }
    while (off + 16u <= len) {
        process_block(data + off, false, 16u);
        off += 16u;
    }
    if (off < len) {
        m_buf_len = len - off;
        mem_copy(m_buf, data + off, m_buf_len);
    }
}

void Poly1305::finalize(u8 tag_out[16]) noexcept {
    if (m_buf_len > 0u) {
        process_block(m_buf, true, m_buf_len);
        m_buf_len = 0u;
    }

    u32 h0 = m_h[0];
    u32 h1 = m_h[1];
    u32 h2 = m_h[2];
    u32 h3 = m_h[3];
    u32 h4 = m_h[4];

    u32 c = h1 >> 26u;
    h1 &= 0x03FFFFFFu;
    h2 += c;
    c = h2 >> 26u;
    h2 &= 0x03FFFFFFu;
    h3 += c;
    c = h3 >> 26u;
    h3 &= 0x03FFFFFFu;
    h4 += c;
    c = h4 >> 26u;
    h4 &= 0x03FFFFFFu;
    h0 += c * 5u;
    c = h0 >> 26u;
    h0 &= 0x03FFFFFFu;
    h1 += c;

    // Compute h + 5 - 2^130 and constant-time select.
    u32 g0 = h0 + 5u;
    c = g0 >> 26u;
    g0 &= 0x03FFFFFFu;
    u32 g1 = h1 + c;
    c = g1 >> 26u;
    g1 &= 0x03FFFFFFu;
    u32 g2 = h2 + c;
    c = g2 >> 26u;
    g2 &= 0x03FFFFFFu;
    u32 g3 = h3 + c;
    c = g3 >> 26u;
    g3 &= 0x03FFFFFFu;
    u32 g4 = h4 + c - (1u << 26u);

    // If g4 underflowed, bit 31 is 1 -> keep h; otherwise select g.
    const u32 mask = (g4 >> 31u) - 1u;
    h0 = ct_select_u32(mask, g0, h0);
    h1 = ct_select_u32(mask, g1, h1);
    h2 = ct_select_u32(mask, g2, h2);
    h3 = ct_select_u32(mask, g3, h3);
    h4 = ct_select_u32(mask, g4, h4);

    // Pack 5 x 26-bit limbs into 4 x 32-bit words and add pad mod 2^128.
    const u32 f0_in = h0 | (h1 << 26u);
    const u32 f1_in = (h1 >> 6u) | (h2 << 20u);
    const u32 f2_in = (h2 >> 12u) | (h3 << 14u);
    const u32 f3_in = (h3 >> 18u) | (h4 << 8u);

    u64 f = as<u64>(f0_in) + m_pad[0];
    store_le32(tag_out + 0u, as<u32>(f));
    f = as<u64>(f1_in) + m_pad[1] + (f >> 32u);
    store_le32(tag_out + 4u, as<u32>(f));
    f = as<u64>(f2_in) + m_pad[2] + (f >> 32u);
    store_le32(tag_out + 8u, as<u32>(f));
    f = as<u64>(f3_in) + m_pad[3] + (f >> 32u);
    store_le32(tag_out + 12u, as<u32>(f));

    secure_zero(m_r, sizeof(m_r));
    secure_zero(m_h, sizeof(m_h));
    secure_zero(m_pad, sizeof(m_pad));
    secure_zero(m_buf, sizeof(m_buf));
}

StaticArray<u8, 16u> Poly1305::finalize() noexcept {
    StaticArray<u8, 16u> tag{};
    finalize(tag.data());
    return tag;
}

StaticArray<u8, 16u> Poly1305::mac(const u8 key[32], ArrayRef<u8> msg) noexcept {
    Poly1305 p(key);
    p.update(msg);
    return p.finalize();
}

bool chacha20_poly1305_encrypt(const u8 key[32], const u8 nonce[12],
                               ArrayRef<u8> aad, ArrayRef<u8> plaintext,
                               MutArrayRef<u8> ciphertext, u8 tag_out[16]) noexcept {
    if (plaintext.size() != ciphertext.size()) return false;
    if (!chacha20_xor(key, 1u, nonce, plaintext, ciphertext)) return false;
    compute_aead_tag(key, nonce, aad, ArrayRef<u8>(ciphertext.data(), ciphertext.size()), tag_out);
    return true;
}

bool chacha20_poly1305_decrypt(const u8 key[32], const u8 nonce[12],
                               ArrayRef<u8> aad, ArrayRef<u8> ciphertext,
                               const u8 tag[16], MutArrayRef<u8> plaintext) noexcept {
    if (ciphertext.size() != plaintext.size()) return false;
    u8 expected[16];
    compute_aead_tag(key, nonce, aad, ciphertext, expected);
    const bool ok = ct_equal(expected, tag, 16u);
    secure_zero(expected, sizeof(expected));
    if (!ok) {
        if (!plaintext.empty()) secure_zero(plaintext.data(), plaintext.size());
        return false;
    }
    return chacha20_xor(key, 1u, nonce, ciphertext, plaintext);
}

bool xchacha20_poly1305_encrypt(const u8 key[32], const u8 nonce[24],
                                ArrayRef<u8> aad, ArrayRef<u8> plaintext,
                                MutArrayRef<u8> ciphertext, u8 tag_out[16]) noexcept {
    u8 subkey[32];
    hchacha20(key, nonce, subkey);
    u8 subnonce[12] = {};
    mem_copy(subnonce + 4u, nonce + 16u, 8u);
    const bool ok = chacha20_poly1305_encrypt(subkey, subnonce, aad, plaintext, ciphertext, tag_out);
    secure_zero(subkey, sizeof(subkey));
    secure_zero(subnonce, sizeof(subnonce));
    return ok;
}

bool xchacha20_poly1305_decrypt(const u8 key[32], const u8 nonce[24],
                                ArrayRef<u8> aad, ArrayRef<u8> ciphertext,
                                const u8 tag[16], MutArrayRef<u8> plaintext) noexcept {
    u8 subkey[32];
    hchacha20(key, nonce, subkey);
    u8 subnonce[12] = {};
    mem_copy(subnonce + 4u, nonce + 16u, 8u);
    const bool ok = chacha20_poly1305_decrypt(subkey, subnonce, aad, ciphertext, tag, plaintext);
    secure_zero(subkey, sizeof(subkey));
    secure_zero(subnonce, sizeof(subnonce));
    return ok;
}

} // namespace keel::crypto
