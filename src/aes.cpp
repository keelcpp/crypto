#include "keel/crypto/aes.h"

#include "keel/crypto/ct.h"
#include "keel/memory.h"

namespace keel::crypto {

namespace {

[[nodiscard]] constexpr u32 load_be32(const u8* p) noexcept {
    return (as<u32>(p[0]) << 24u) | (as<u32>(p[1]) << 16u) | (as<u32>(p[2]) << 8u) | as<u32>(p[3]);
}

constexpr void store_be32(u8* p, u32 v) noexcept {
    p[0] = as<u8>((v >> 24u) & 0xFFu);
    p[1] = as<u8>((v >> 16u) & 0xFFu);
    p[2] = as<u8>((v >> 8u) & 0xFFu);
    p[3] = as<u8>(v & 0xFFu);
}

[[nodiscard]] constexpr u64 load_be64(const u8* p) noexcept {
    return (as<u64>(p[0]) << 56u) | (as<u64>(p[1]) << 48u) | (as<u64>(p[2]) << 40u) |
           (as<u64>(p[3]) << 32u) | (as<u64>(p[4]) << 24u) | (as<u64>(p[5]) << 16u) |
           (as<u64>(p[6]) << 8u) | as<u64>(p[7]);
}

constexpr void store_be64(u8* p, u64 v) noexcept {
    p[0] = as<u8>((v >> 56u) & 0xFFu);
    p[1] = as<u8>((v >> 48u) & 0xFFu);
    p[2] = as<u8>((v >> 40u) & 0xFFu);
    p[3] = as<u8>((v >> 32u) & 0xFFu);
    p[4] = as<u8>((v >> 24u) & 0xFFu);
    p[5] = as<u8>((v >> 16u) & 0xFFu);
    p[6] = as<u8>((v >> 8u) & 0xFFu);
    p[7] = as<u8>(v & 0xFFu);
}

[[nodiscard]] constexpr u8 rotl8(u8 x, u32 n) noexcept {
    return as<u8>((as<u32>(x) << n) | (as<u32>(x) >> (8u - n)));
}

// Branchless multiplication in GF(2^8) modulo x^8 + x^4 + x^3 + x + 1 (0x11B).
[[nodiscard]] constexpr u8 gf_mul(u8 a, u8 b) noexcept {
    u8 p = 0u;
    for (u32 i = 0u; i < 8u; ++i) {
        const u8 bit_mask = as<u8>(0u - as<u32>(b & 1u));
        p = as<u8>(p ^ (a & bit_mask));
        const u8 hi_mask = as<u8>(0u - as<u32>((a >> 7u) & 1u));
        a = as<u8>((a << 1u) ^ (0x1Bu & hi_mask));
        b = as<u8>(b >> 1u);
    }
    return p;
}

[[nodiscard]] constexpr u8 gf_xtime(u8 a) noexcept {
    const u8 hi_mask = as<u8>(0u - as<u32>((a >> 7u) & 1u));
    return as<u8>((a << 1u) ^ (0x1Bu & hi_mask));
}

// Constant-time multiplicative inverse in GF(2^8): a^254 (maps 0 -> 0).
[[nodiscard]] constexpr u8 gf_inv(u8 a) noexcept {
    const u8 a2 = gf_mul(a, a);
    const u8 a3 = gf_mul(a2, a);
    const u8 a6 = gf_mul(a3, a3);
    const u8 a12 = gf_mul(a6, a6);
    const u8 a14 = gf_mul(a12, a2);
    const u8 a15 = gf_mul(a14, a);
    const u8 a30 = gf_mul(a15, a15);
    const u8 a60 = gf_mul(a30, a30);
    const u8 a120 = gf_mul(a60, a60);
    const u8 a126 = gf_mul(a120, a6);
    const u8 a127 = gf_mul(a126, a);
    return gf_mul(a127, a127);
}

[[nodiscard]] constexpr u8 sbox(u8 a) noexcept {
    const u8 x = gf_inv(a);
    return as<u8>(x ^ rotl8(x, 1u) ^ rotl8(x, 2u) ^ rotl8(x, 3u) ^ rotl8(x, 4u) ^ 0x63u);
}

[[nodiscard]] constexpr u8 inv_sbox(u8 a) noexcept {
    const u8 y = as<u8>(rotl8(a, 1u) ^ rotl8(a, 3u) ^ rotl8(a, 6u) ^ 0x05u);
    return gf_inv(y);
}

[[nodiscard]] constexpr u32 sub_word(u32 w) noexcept {
    return (as<u32>(sbox(as<u8>(w >> 24u))) << 24u) |
           (as<u32>(sbox(as<u8>((w >> 16u) & 0xFFu))) << 16u) |
           (as<u32>(sbox(as<u8>((w >> 8u) & 0xFFu))) << 8u) |
           as<u32>(sbox(as<u8>(w & 0xFFu)));
}

[[nodiscard]] constexpr u32 rot_word(u32 w) noexcept {
    return (w << 8u) | (w >> 24u);
}

void add_round_key(u8 s[16], const u32 rk[4]) noexcept {
    for (usize c = 0u; c < 4u; ++c) {
        const u32 w = rk[c];
        s[4u * c + 0u] = as<u8>(s[4u * c + 0u] ^ as<u8>((w >> 24u) & 0xFFu));
        s[4u * c + 1u] = as<u8>(s[4u * c + 1u] ^ as<u8>((w >> 16u) & 0xFFu));
        s[4u * c + 2u] = as<u8>(s[4u * c + 2u] ^ as<u8>((w >> 8u) & 0xFFu));
        s[4u * c + 3u] = as<u8>(s[4u * c + 3u] ^ as<u8>(w & 0xFFu));
    }
}

void sub_bytes(u8 s[16]) noexcept {
    for (usize i = 0u; i < 16u; ++i) s[i] = sbox(s[i]);
}

void inv_sub_bytes(u8 s[16]) noexcept {
    for (usize i = 0u; i < 16u; ++i) s[i] = inv_sbox(s[i]);
}

void shift_rows(u8 s[16]) noexcept {
    u8 t = s[1];
    s[1] = s[5];
    s[5] = s[9];
    s[9] = s[13];
    s[13] = t;

    t = s[2];
    s[2] = s[10];
    s[10] = t;
    t = s[6];
    s[6] = s[14];
    s[14] = t;

    t = s[15];
    s[15] = s[11];
    s[11] = s[7];
    s[7] = s[3];
    s[3] = t;
}

void inv_shift_rows(u8 s[16]) noexcept {
    u8 t = s[13];
    s[13] = s[9];
    s[9] = s[5];
    s[5] = s[1];
    s[1] = t;

    t = s[2];
    s[2] = s[10];
    s[10] = t;
    t = s[6];
    s[6] = s[14];
    s[14] = t;

    t = s[3];
    s[3] = s[7];
    s[7] = s[11];
    s[11] = s[15];
    s[15] = t;
}

void mix_columns(u8 s[16]) noexcept {
    for (usize c = 0u; c < 4u; ++c) {
        const usize i = 4u * c;
        const u8 a0 = s[i + 0u];
        const u8 a1 = s[i + 1u];
        const u8 a2 = s[i + 2u];
        const u8 a3 = s[i + 3u];
        const u8 x = as<u8>(a0 ^ a1 ^ a2 ^ a3);
        s[i + 0u] = as<u8>(a0 ^ x ^ gf_xtime(as<u8>(a0 ^ a1)));
        s[i + 1u] = as<u8>(a1 ^ x ^ gf_xtime(as<u8>(a1 ^ a2)));
        s[i + 2u] = as<u8>(a2 ^ x ^ gf_xtime(as<u8>(a2 ^ a3)));
        s[i + 3u] = as<u8>(a3 ^ x ^ gf_xtime(as<u8>(a3 ^ a0)));
    }
}

void inv_mix_columns(u8 s[16]) noexcept {
    for (usize c = 0u; c < 4u; ++c) {
        const usize i = 4u * c;
        const u8 a0 = s[i + 0u];
        const u8 a1 = s[i + 1u];
        const u8 a2 = s[i + 2u];
        const u8 a3 = s[i + 3u];
        const u8 u = gf_xtime(gf_xtime(as<u8>(a0 ^ a2)));
        const u8 v = gf_xtime(gf_xtime(as<u8>(a1 ^ a3)));
        s[i + 0u] = as<u8>(a0 ^ u);
        s[i + 1u] = as<u8>(a1 ^ v);
        s[i + 2u] = as<u8>(a2 ^ u);
        s[i + 3u] = as<u8>(a3 ^ v);
    }
    mix_columns(s);
}

void inc_be128(u8 ctr[16]) noexcept {
    for (usize i = 16u; i-- > 0u;) {
        ctr[i] = as<u8>(ctr[i] + 1u);
        if (ctr[i] != 0u) break;
    }
}

void inc_be32(u8 ctr[16]) noexcept {
    const u32 c = load_be32(ctr + 12u) + 1u;
    store_be32(ctr + 12u, c);
}

// Constant-time multiplication in GF(2^128) (NIST SP 800-38D Algorithm 1).
void ghash_mul(const u8 h_bytes[16], u8 y_bytes[16]) noexcept {
    u64 v_hi = load_be64(h_bytes);
    u64 v_lo = load_be64(h_bytes + 8u);
    const u64 x_hi = load_be64(y_bytes);
    const u64 x_lo = load_be64(y_bytes + 8u);

    u64 z_hi = 0u;
    u64 z_lo = 0u;

    for (u32 i = 0u; i < 64u; ++i) {
        const u64 bit = (x_hi >> (63u - i)) & 1u;
        const u64 mask = 0u - bit;
        z_hi ^= (v_hi & mask);
        z_lo ^= (v_lo & mask);

        const u64 lsb = 0u - (v_lo & 1u);
        v_lo = (v_lo >> 1u) | (v_hi << 63u);
        v_hi = (v_hi >> 1u) ^ (0xE100000000000000ull & lsb);
    }
    for (u32 i = 0u; i < 64u; ++i) {
        const u64 bit = (x_lo >> (63u - i)) & 1u;
        const u64 mask = 0u - bit;
        z_hi ^= (v_hi & mask);
        z_lo ^= (v_lo & mask);

        const u64 lsb = 0u - (v_lo & 1u);
        v_lo = (v_lo >> 1u) | (v_hi << 63u);
        v_hi = (v_hi >> 1u) ^ (0xE100000000000000ull & lsb);
    }

    store_be64(y_bytes, z_hi);
    store_be64(y_bytes + 8u, z_lo);
}

void ghash_update(const u8 h[16], u8 acc[16], const u8* data, usize len) noexcept {
    usize off = 0u;
    while (off + 16u <= len) {
        for (usize i = 0u; i < 16u; ++i) acc[i] = as<u8>(acc[i] ^ data[off + i]);
        ghash_mul(h, acc);
        off += 16u;
    }
    if (off < len) {
        const usize rem = len - off;
        for (usize i = 0u; i < rem; ++i) acc[i] = as<u8>(acc[i] ^ data[off + i]);
        ghash_mul(h, acc);
    }
}

void gcm_compute_j0(const u8 h[16], ArrayRef<u8> nonce, u8 j0[16]) noexcept {
    mem_zero(j0, 16u);
    if (nonce.size() == 12u) {
        mem_copy(j0, nonce.data(), 12u);
        j0[15] = 1u;
        return;
    }
    ghash_update(h, j0, nonce.data(), nonce.size());
    u8 len_blk[16] = {};
    store_be64(len_blk + 8u, as<u64>(nonce.size()) * 8u);
    ghash_update(h, j0, len_blk, 16u);
}

void gctr_xor(const Aes& aes, const u8 icb[16], const u8* in, u8* out, usize len) noexcept {
    u8 cb[16];
    mem_copy(cb, icb, 16u);
    u8 ks[16];
    usize off = 0u;
    while (off < len) {
        aes.encrypt_block(cb, ks);
        inc_be32(cb);
        const usize n = (len - off < 16u) ? (len - off) : 16u;
        for (usize i = 0u; i < n; ++i) out[off + i] = as<u8>(in[off + i] ^ ks[i]);
        off += n;
    }
    secure_zero(cb, sizeof(cb));
    secure_zero(ks, sizeof(ks));
}

} // namespace

Aes::~Aes() noexcept {
    secure_zero(m_rk, sizeof(m_rk));
    m_rounds = 0u;
}

Aes::Aes(Aes&& other) noexcept : m_rounds(other.m_rounds) {
    mem_copy(m_rk, other.m_rk, sizeof(m_rk));
    secure_zero(other.m_rk, sizeof(other.m_rk));
    other.m_rounds = 0u;
}

Aes& Aes::operator=(Aes&& other) noexcept {
    if (this != &other) {
        mem_copy(m_rk, other.m_rk, sizeof(m_rk));
        m_rounds = other.m_rounds;
        secure_zero(other.m_rk, sizeof(other.m_rk));
        other.m_rounds = 0u;
    }
    return *this;
}

bool Aes::init(ArrayRef<u8> key) noexcept {
    secure_zero(m_rk, sizeof(m_rk));
    m_rounds = 0u;

    usize nk = 0u;
    usize nr = 0u;
    if (key.size() == 16u) {
        nk = 4u;
        nr = 10u;
    } else if (key.size() == 24u) {
        nk = 6u;
        nr = 12u;
    } else if (key.size() == 32u) {
        nk = 8u;
        nr = 14u;
    } else {
        return false;
    }

    static constexpr u8 kRcon[11] = {
        0x00u, 0x01u, 0x02u, 0x04u, 0x08u, 0x10u, 0x20u, 0x40u, 0x80u, 0x1Bu, 0x36u,
    };

    for (usize i = 0u; i < nk; ++i) m_rk[i] = load_be32(key.data() + 4u * i);

    const usize total_words = 4u * (nr + 1u);
    for (usize i = nk; i < total_words; ++i) {
        u32 temp = m_rk[i - 1u];
        if ((i % nk) == 0u) {
            temp = sub_word(rot_word(temp)) ^ (as<u32>(kRcon[i / nk]) << 24u);
        } else if (nk == 8u && (i % nk) == 4u) {
            temp = sub_word(temp);
        }
        m_rk[i] = m_rk[i - nk] ^ temp;
    }
    m_rounds = nr;
    return true;
}

void Aes::encrypt_block(const u8 in[16], u8 out[16]) const noexcept {
    if (m_rounds == 0u) {
        mem_zero(out, 16u);
        return;
    }
    u8 state[16];
    mem_copy(state, in, 16u);

    add_round_key(state, m_rk);
    for (usize r = 1u; r < m_rounds; ++r) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, m_rk + 4u * r);
    }
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, m_rk + 4u * m_rounds);

    mem_copy(out, state, 16u);
    secure_zero(state, sizeof(state));
}

void Aes::decrypt_block(const u8 in[16], u8 out[16]) const noexcept {
    if (m_rounds == 0u) {
        mem_zero(out, 16u);
        return;
    }
    u8 state[16];
    mem_copy(state, in, 16u);

    add_round_key(state, m_rk + 4u * m_rounds);
    for (usize r = m_rounds - 1u; r >= 1u; --r) {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, m_rk + 4u * r);
        inv_mix_columns(state);
    }
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, m_rk);

    mem_copy(out, state, 16u);
    secure_zero(state, sizeof(state));
}

bool aes_ctr_xor(ArrayRef<u8> key, const u8 iv[16], ArrayRef<u8> in,
                 MutArrayRef<u8> out) noexcept {
    if (in.size() != out.size()) return false;
    Aes aes;
    if (!aes.init(key)) return false;

    u8 ctr[16];
    mem_copy(ctr, iv, 16u);
    u8 ks[16];
    usize off = 0u;
    while (off < in.size()) {
        aes.encrypt_block(ctr, ks);
        inc_be128(ctr);
        const usize n = (in.size() - off < 16u) ? (in.size() - off) : 16u;
        for (usize i = 0u; i < n; ++i) out[off + i] = as<u8>(in[off + i] ^ ks[i]);
        off += n;
    }
    secure_zero(ctr, sizeof(ctr));
    secure_zero(ks, sizeof(ks));
    return true;
}

bool aes_cbc_encrypt_blocks(ArrayRef<u8> key, const u8 iv[16], ArrayRef<u8> in,
                            MutArrayRef<u8> out) noexcept {
    if ((in.size() % 16u) != 0u || in.size() != out.size()) return false;
    Aes aes;
    if (!aes.init(key)) return false;

    u8 prev[16];
    mem_copy(prev, iv, 16u);
    u8 blk[16];
    for (usize off = 0u; off < in.size(); off += 16u) {
        for (usize i = 0u; i < 16u; ++i) blk[i] = as<u8>(in[off + i] ^ prev[i]);
        aes.encrypt_block(blk, out.data() + off);
        mem_copy(prev, out.data() + off, 16u);
    }
    secure_zero(prev, sizeof(prev));
    secure_zero(blk, sizeof(blk));
    return true;
}

bool aes_cbc_decrypt_blocks(ArrayRef<u8> key, const u8 iv[16], ArrayRef<u8> in,
                            MutArrayRef<u8> out) noexcept {
    if ((in.size() % 16u) != 0u || in.size() != out.size()) return false;
    Aes aes;
    if (!aes.init(key)) return false;

    u8 prev[16];
    mem_copy(prev, iv, 16u);
    u8 cur[16];
    u8 dec[16];
    for (usize off = 0u; off < in.size(); off += 16u) {
        mem_copy(cur, in.data() + off, 16u);
        aes.decrypt_block(cur, dec);
        for (usize i = 0u; i < 16u; ++i) out[off + i] = as<u8>(dec[i] ^ prev[i]);
        mem_copy(prev, cur, 16u);
    }
    secure_zero(prev, sizeof(prev));
    secure_zero(cur, sizeof(cur));
    secure_zero(dec, sizeof(dec));
    return true;
}

Optional<Array<u8>> aes_cbc_encrypt(ArrayRef<u8> key, const u8 iv[16], ArrayRef<u8> plaintext,
                                    Allocator* alloc) {
    Aes aes;
    if (!aes.init(key)) return Optional<Array<u8>>{};

    const usize pad_len = 16u - (plaintext.size() % 16u);
    const usize total = plaintext.size() + pad_len;
    Array<u8> out(total, u8{0u}, alloc);

    u8 prev[16];
    mem_copy(prev, iv, 16u);
    u8 blk[16];
    usize off = 0u;
    while (off + 16u <= plaintext.size()) {
        for (usize i = 0u; i < 16u; ++i) blk[i] = as<u8>(plaintext[off + i] ^ prev[i]);
        aes.encrypt_block(blk, out.data() + off);
        mem_copy(prev, out.data() + off, 16u);
        off += 16u;
    }
    const usize rem = plaintext.size() - off;
    for (usize i = 0u; i < rem; ++i) blk[i] = as<u8>(plaintext[off + i] ^ prev[i]);
    for (usize i = rem; i < 16u; ++i) blk[i] = as<u8>(as<u8>(pad_len) ^ prev[i]);
    aes.encrypt_block(blk, out.data() + off);

    secure_zero(prev, sizeof(prev));
    secure_zero(blk, sizeof(blk));
    return out;
}

Optional<Array<u8>> aes_cbc_decrypt(ArrayRef<u8> key, const u8 iv[16], ArrayRef<u8> ciphertext,
                                    Allocator* alloc) {
    if (ciphertext.empty() || (ciphertext.size() % 16u) != 0u) return Optional<Array<u8>>{};
    Array<u8> out(ciphertext.size(), u8{0u}, alloc);
    if (!aes_cbc_decrypt_blocks(key, iv, ciphertext, out.as_mut_ref())) {
        secure_zero(out.data(), out.size());
        return Optional<Array<u8>>{};
    }

    // Constant-time PKCS#7 padding check over the final 16-byte block.
    const u8* last = out.data() + (out.size() - 16u);
    const u32 pad = as<u32>(last[15]);
    u32 bad = 0u;
    // pad must be in [1, 16]: check (pad - 1) >= 16 via unsigned wrap.
    bad |= ((pad - 1u) >> 4u);
    for (u32 i = 0u; i < 16u; ++i) {
        const u32 in_pad = (i >= (16u - pad)) ? 1u : 0u;
        const u32 mask = 0u - in_pad;
        bad |= (as<u32>(last[i]) ^ pad) & mask;
    }
    if (bad != 0u) {
        secure_zero(out.data(), out.size());
        return Optional<Array<u8>>{};
    }
    out.resize(out.size() - as<usize>(pad));
    return out;
}

bool aes_gcm_encrypt(ArrayRef<u8> key, ArrayRef<u8> nonce, ArrayRef<u8> aad,
                     ArrayRef<u8> plaintext, MutArrayRef<u8> ciphertext,
                     u8 tag_out[16]) noexcept {
    if (nonce.empty() || plaintext.size() != ciphertext.size()) return false;
    Aes aes;
    if (!aes.init(key)) return false;

    u8 h[16] = {};
    aes.encrypt_block(h, h);

    u8 j0[16];
    gcm_compute_j0(h, nonce, j0);

    u8 icb[16];
    mem_copy(icb, j0, 16u);
    inc_be32(icb);
    gctr_xor(aes, icb, plaintext.data(), ciphertext.data(), plaintext.size());

    u8 s[16] = {};
    ghash_update(h, s, aad.data(), aad.size());
    ghash_update(h, s, ciphertext.data(), ciphertext.size());
    u8 lens[16];
    store_be64(lens, as<u64>(aad.size()) * 8u);
    store_be64(lens + 8u, as<u64>(ciphertext.size()) * 8u);
    ghash_update(h, s, lens, 16u);

    u8 ej0[16];
    aes.encrypt_block(j0, ej0);
    for (usize i = 0u; i < 16u; ++i) tag_out[i] = as<u8>(s[i] ^ ej0[i]);

    secure_zero(h, sizeof(h));
    secure_zero(j0, sizeof(j0));
    secure_zero(icb, sizeof(icb));
    secure_zero(s, sizeof(s));
    secure_zero(ej0, sizeof(ej0));
    return true;
}

bool aes_gcm_decrypt(ArrayRef<u8> key, ArrayRef<u8> nonce, ArrayRef<u8> aad,
                     ArrayRef<u8> ciphertext, const u8 tag[16],
                     MutArrayRef<u8> plaintext) noexcept {
    if (nonce.empty() || ciphertext.size() != plaintext.size()) return false;
    Aes aes;
    if (!aes.init(key)) return false;

    u8 h[16] = {};
    aes.encrypt_block(h, h);

    u8 j0[16];
    gcm_compute_j0(h, nonce, j0);

    // Compute GHASH over AAD and ciphertext BEFORE decrypting so we can authenticate
    // even when `ciphertext` and `plaintext` alias in memory.
    u8 s[16] = {};
    ghash_update(h, s, aad.data(), aad.size());
    ghash_update(h, s, ciphertext.data(), ciphertext.size());
    u8 lens[16];
    store_be64(lens, as<u64>(aad.size()) * 8u);
    store_be64(lens + 8u, as<u64>(ciphertext.size()) * 8u);
    ghash_update(h, s, lens, 16u);

    u8 ej0[16];
    aes.encrypt_block(j0, ej0);
    u8 expected_tag[16];
    for (usize i = 0u; i < 16u; ++i) expected_tag[i] = as<u8>(s[i] ^ ej0[i]);

    const bool ok = ct_equal(expected_tag, tag, 16u);
    if (ok) {
        u8 icb[16];
        mem_copy(icb, j0, 16u);
        inc_be32(icb);
        gctr_xor(aes, icb, ciphertext.data(), plaintext.data(), ciphertext.size());
        secure_zero(icb, sizeof(icb));
    } else if (!plaintext.empty()) {
        secure_zero(plaintext.data(), plaintext.size());
    }

    secure_zero(h, sizeof(h));
    secure_zero(j0, sizeof(j0));
    secure_zero(s, sizeof(s));
    secure_zero(ej0, sizeof(ej0));
    secure_zero(expected_tag, sizeof(expected_tag));
    return ok;
}

} // namespace keel::crypto
