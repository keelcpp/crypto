#include "keel/crypto/curve25519.h"

#include "keel/crypto/ct.h"
#include "keel/crypto/digest.h"
#include "keel/memory.h"

namespace keel::crypto {

namespace {

// ---------------------------------------------------------------------------
// Constant-time GF(2^255 - 19) field arithmetic using 16 signed 16-bit limbs.
// Fully portable C++20 (no __int128 or platform intrinsics required).
// ---------------------------------------------------------------------------
struct Fe {
    i64 v[16];
};

inline void fe_zero(Fe& o) noexcept {
    for (usize i = 0u; i < 16u; ++i) o.v[i] = 0;
}

inline void fe_one(Fe& o) noexcept {
    fe_zero(o);
    o.v[0] = 1;
}

inline void fe_copy(Fe& o, const Fe& a) noexcept {
    for (usize i = 0u; i < 16u; ++i) o.v[i] = a.v[i];
}

inline void fe_cswap(Fe& p, Fe& q, u64 b) noexcept {
    const i64 mask = -as<i64>(b & 1u);
    for (usize i = 0u; i < 16u; ++i) {
        const i64 t = mask & (p.v[i] ^ q.v[i]);
        p.v[i] ^= t;
        q.v[i] ^= t;
    }
}

inline void fe_carry(Fe& o) noexcept {
    for (usize i = 0u; i < 16u; ++i) {
        const i64 c = o.v[i] >> 16;
        o.v[i] -= c * 65536;
        if (i < 15u) {
            o.v[i + 1u] += c;
        } else {
            o.v[0] += c * 38;
        }
    }
}

inline void fe_add(Fe& o, const Fe& a, const Fe& b) noexcept {
    for (usize i = 0u; i < 16u; ++i) o.v[i] = a.v[i] + b.v[i];
}

inline void fe_sub(Fe& o, const Fe& a, const Fe& b) noexcept {
    for (usize i = 0u; i < 16u; ++i) o.v[i] = a.v[i] - b.v[i];
}

inline void fe_neg(Fe& o, const Fe& a) noexcept {
    for (usize i = 0u; i < 16u; ++i) o.v[i] = -a.v[i];
}

void fe_mul(Fe& o, const Fe& a, const Fe& b) noexcept {
    i64 t[31] = {};
    for (usize i = 0u; i < 16u; ++i) {
        for (usize j = 0u; j < 16u; ++j) {
            t[i + j] += a.v[i] * b.v[j];
        }
    }
    for (usize i = 0u; i < 15u; ++i) {
        t[i] += 38 * t[i + 16u];
    }
    for (usize i = 0u; i < 16u; ++i) {
        o.v[i] = t[i];
    }
    fe_carry(o);
    fe_carry(o);
}

inline void fe_sq(Fe& o, const Fe& a) noexcept {
    fe_mul(o, a, a);
}

void fe_unpack(Fe& o, const u8 in[32]) noexcept {
    for (usize i = 0u; i < 16u; ++i) {
        o.v[i] = as<i64>(in[2u * i]) | (as<i64>(in[2u * i + 1u]) << 8);
    }
    o.v[15] &= 0x7fff;
}

void fe_pack(u8 out[32], const Fe& n) noexcept {
    Fe t;
    Fe m;
    fe_copy(t, n);
    fe_carry(t);
    fe_carry(t);
    fe_carry(t);
    for (usize j = 0u; j < 2u; ++j) {
        m.v[0] = t.v[0] - 0xffed;
        for (usize i = 1u; i < 15u; ++i) {
            m.v[i] = t.v[i] - 0xffff - ((m.v[i - 1u] >> 16) & 1);
            m.v[i - 1u] &= 0xffff;
        }
        m.v[15] = t.v[15] - 0x7fff - ((m.v[14] >> 16) & 1);
        const u64 borrow = as<u64>((m.v[15] >> 16) & 1);
        m.v[14] &= 0xffff;
        fe_cswap(t, m, 1u - borrow);
    }
    for (usize i = 0u; i < 16u; ++i) {
        out[2u * i] = as<u8>(t.v[i] & 0xff);
        out[2u * i + 1u] = as<u8>((t.v[i] >> 8) & 0xff);
    }
}

bool fe_equal(const Fe& a, const Fe& b) noexcept {
    u8 sa[32];
    u8 sb[32];
    fe_pack(sa, a);
    fe_pack(sb, b);
    const bool eq = ct_equal(ArrayRef<u8>(sa, 32u), ArrayRef<u8>(sb, 32u));
    secure_zero(sa, sizeof(sa));
    secure_zero(sb, sizeof(sb));
    return eq;
}

u8 fe_parity(const Fe& a) noexcept {
    u8 s[32];
    fe_pack(s, a);
    const u8 bit = as<u8>(s[0] & 1u);
    secure_zero(s, sizeof(s));
    return bit;
}

// Compute a^(p - 2) = a^(2^255 - 21) mod p.
void fe_inv(Fe& o, const Fe& a) noexcept {
    Fe c;
    fe_copy(c, a);
    for (usize idx = 254u; idx-- > 0u;) {
        fe_sq(c, c);
        if (idx != 2u && idx != 4u) {
            fe_mul(c, c, a);
        }
    }
    fe_copy(o, c);
}

// Compute a^((p - 5) / 8) = a^(2^252 - 3) mod p.
void fe_pow2523(Fe& o, const Fe& a) noexcept {
    Fe c;
    fe_copy(c, a);
    for (usize idx = 251u; idx-- > 0u;) {
        fe_sq(c, c);
        if (idx != 1u) {
            fe_mul(c, c, a);
        }
    }
    fe_copy(o, c);
}

// ---------------------------------------------------------------------------
// Curve25519 / Edwards25519 constants
// ---------------------------------------------------------------------------

// (A - 2) / 4 = 121665 for X25519 Montgomery ladder.
constexpr Fe kA24 = {{0xdb41, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};

// d = -121665 / 121666 mod p
constexpr Fe kD = {{
    0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070,
    0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203
}};

// 2 * d mod p
constexpr Fe kD2 = {{
    0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0,
    0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406
}};

// sqrt(-1) = 2^((p - 1) / 4) mod p
constexpr Fe kSqrtM1 = {{
    0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43,
    0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83
}};

// Ed25519 base point B = (Bx, By)
constexpr Fe kBx = {{
    0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c,
    0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169
}};

constexpr Fe kBy = {{
    0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
    0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666
}};

// Group order L = 2^252 + 27742317777372353535851937790883648493 (little-endian bytes)
constexpr u8 kOrderL[32] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
};

// Prime p = 2^255 - 19 (little-endian bytes) for canonical y < p check.
constexpr u8 kPrimeP[32] = {
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f
};

// Constant-time check a < b for 32-byte little-endian unsigned integers.
bool le32_less(const u8 a[32], const u8 b[32]) noexcept {
    u32 borrow = 0u;
    for (usize i = 0u; i < 32u; ++i) {
        const u32 diff = as<u32>(a[i]) - as<u32>(b[i]) - borrow;
        borrow = (diff >> 31u) & 1u;
    }
    return borrow != 0u;
}

// ---------------------------------------------------------------------------
// Extended Twisted Edwards point (X : Y : Z : T) with x = X/Z, y = Y/Z, xy = T/Z
// ---------------------------------------------------------------------------
struct GePoint {
    Fe x;
    Fe y;
    Fe z;
    Fe t;
};

void ge_identity(GePoint& p) noexcept {
    fe_zero(p.x);
    fe_one(p.y);
    fe_one(p.z);
    fe_zero(p.t);
}

void ge_basepoint(GePoint& p) noexcept {
    fe_copy(p.x, kBx);
    fe_copy(p.y, kBy);
    fe_one(p.z);
    fe_mul(p.t, p.x, p.y);
}

void ge_cswap(GePoint& p, GePoint& q, u64 b) noexcept {
    fe_cswap(p.x, q.x, b);
    fe_cswap(p.y, q.y, b);
    fe_cswap(p.z, q.z, b);
    fe_cswap(p.t, q.t, b);
}

// Unified complete extended Edwards point addition: p = p + q (works for doubling & identity).
void ge_add(GePoint& out, const GePoint& p, const GePoint& q) noexcept {
    Fe a, b, c, d, e, f, g, h, t;
    fe_sub(a, p.y, p.x);
    fe_sub(t, q.y, q.x);
    fe_mul(a, a, t);

    fe_add(b, p.x, p.y);
    fe_add(t, q.x, q.y);
    fe_mul(b, b, t);

    fe_mul(c, p.t, q.t);
    fe_mul(c, c, kD2);

    fe_mul(d, p.z, q.z);
    fe_add(d, d, d);

    fe_sub(e, b, a);
    fe_sub(f, d, c);
    fe_add(g, d, c);
    fe_add(h, b, a);

    fe_mul(out.x, e, f);
    fe_mul(out.y, g, h);
    fe_mul(out.z, f, g);
    fe_mul(out.t, e, h);
}

// Constant-time scalar multiplication: out = [scalar] * point.
void ge_scalarmult(GePoint& out, const GePoint& point, const u8 scalar[32]) noexcept {
    GePoint r0;
    GePoint r1;
    ge_identity(r0);
    r1 = point;

    for (usize i = 256u; i-- > 0u;) {
        const u64 bit = as<u64>((scalar[i >> 3u] >> (i & 7u)) & 1u);
        ge_cswap(r0, r1, bit);
        ge_add(r1, r1, r0);
        ge_add(r0, r0, r0);
        ge_cswap(r0, r1, bit);
    }
    out = r0;
}

void ge_scalarmult_base(GePoint& out, const u8 scalar[32]) noexcept {
    GePoint base;
    ge_basepoint(base);
    ge_scalarmult(out, base, scalar);
}

void ge_pack(u8 out[32], const GePoint& p) noexcept {
    Fe zi, tx, ty;
    fe_inv(zi, p.z);
    fe_mul(tx, p.x, zi);
    fe_mul(ty, p.y, zi);
    fe_pack(out, ty);
    out[31] ^= as<u8>(fe_parity(tx) << 7u);
}

bool ge_unpack_neg(GePoint& out, const u8 in[32]) noexcept {
    // Reject non-canonical y >= p (RFC 8032 §5.1.3).
    u8 y_bytes[32];
    mem_copy(y_bytes, in, 32u);
    y_bytes[31] &= 0x7fu;
    if (!le32_less(y_bytes, kPrimeP)) {
        return false;
    }

    fe_unpack(out.y, in);
    fe_one(out.z);

    Fe u, v, check, t;
    fe_sq(u, out.y);           // y^2
    fe_mul(v, u, kD);          // d * y^2
    fe_sub(u, u, out.z);       // u = y^2 - 1
    fe_add(v, v, out.z);       // v = d * y^2 + 1

    // Candidate x = u * v^3 * (u * v^7)^((p - 5) / 8)
    Fe v3, uv7;
    fe_sq(t, v);               // v^2
    fe_mul(v3, t, v);          // v^3
    fe_sq(uv7, v3);            // v^6
    fe_mul(uv7, uv7, v);       // v^7
    fe_mul(uv7, uv7, u);       // u * v^7
    fe_pow2523(out.x, uv7);
    fe_mul(out.x, out.x, v3);
    fe_mul(out.x, out.x, u);

    fe_sq(check, out.x);
    fe_mul(check, check, v);
    if (!fe_equal(check, u)) {
        fe_mul(out.x, out.x, kSqrtM1);
        fe_sq(check, out.x);
        fe_mul(check, check, v);
        if (!fe_equal(check, u)) {
            return false;
        }
    }

    const u8 sign_bit = as<u8>(in[31] >> 7u);
    Fe zero;
    fe_zero(zero);
    if (fe_equal(out.x, zero) && sign_bit != 0u) {
        return false;
    }

    // We want -P = (-x, y), so x should have parity OPPOSITE to sign_bit
    // (or flip when fe_parity(out.x) == sign_bit).
    if (fe_parity(out.x) == sign_bit) {
        fe_neg(out.x, out.x);
    }
    fe_mul(out.t, out.x, out.y);
    return true;
}

// Reduce a 64-byte little-endian integer (held in x[0..63]) modulo L into r[0..31].
void sc_mod_l(u8 r[32], i64 x[64]) noexcept {
    for (usize i = 63u; i >= 32u; --i) {
        i64 carry = 0;
        const usize k = i - 12u;
        for (usize j = i - 32u; j < k; ++j) {
            x[j] += carry - 16 * x[i] * as<i64>(kOrderL[j - (i - 32u)]);
            carry = (x[j] + 128) >> 8;
            x[j] -= carry * 256;
        }
        x[k] += carry;
        x[i] = 0;
    }

    i64 carry = 0;
    for (usize j = 0u; j < 32u; ++j) {
        x[j] += carry - (x[31] >> 4) * as<i64>(kOrderL[j]);
        carry = x[j] >> 8;
        x[j] &= 255;
    }
    for (usize j = 0u; j < 32u; ++j) {
        x[j] -= carry * as<i64>(kOrderL[j]);
    }
    for (usize i = 0u; i < 32u; ++i) {
        x[i + 1u] += x[i] >> 8;
        r[i] = as<u8>(x[i] & 255);
    }
}

void sc_reduce64(u8 out[32], const u8 in[64]) noexcept {
    i64 x[64];
    for (usize i = 0u; i < 64u; ++i) x[i] = as<i64>(in[i]);
    sc_mod_l(out, x);
    secure_zero(x, sizeof(x));
}

void clamp_scalar(u8 s[32]) noexcept {
    s[0] &= 248u;
    s[31] &= 127u;
    s[31] |= 64u;
}

} // namespace

// ---------------------------------------------------------------------------
// X25519 (RFC 7748)
// ---------------------------------------------------------------------------
bool x25519(const u8 scalar[32], const u8 peer_public[32], u8 shared_out[32]) noexcept {
    u8 e[32];
    mem_copy(e, scalar, 32u);
    clamp_scalar(e);

    Fe x1, x2, z2, x3, z3;
    fe_unpack(x1, peer_public);
    fe_one(x2);
    fe_zero(z2);
    fe_copy(x3, x1);
    fe_one(z3);

    u64 do_swap = 0u;
    Fe a, aa, b, bb, ee, c, d, da, cb;
    for (usize pos = 255u; pos-- > 0u;) {
        const u64 kt = as<u64>((e[pos >> 3u] >> (pos & 7u)) & 1u);
        do_swap ^= kt;
        fe_cswap(x2, x3, do_swap);
        fe_cswap(z2, z3, do_swap);
        do_swap = kt;

        fe_add(a, x2, z2);
        fe_sq(aa, a);
        fe_sub(b, x2, z2);
        fe_sq(bb, b);
        fe_sub(ee, aa, bb);
        fe_add(c, x3, z3);
        fe_sub(d, x3, z3);
        fe_mul(da, d, a);
        fe_mul(cb, c, b);

        fe_add(x3, da, cb);
        fe_sq(x3, x3);

        fe_sub(z3, da, cb);
        fe_sq(z3, z3);
        fe_mul(z3, z3, x1);

        fe_mul(x2, aa, bb);
        fe_mul(z2, ee, kA24);
        fe_add(z2, z2, aa);
        fe_mul(z2, z2, ee);
    }
    fe_cswap(x2, x3, do_swap);
    fe_cswap(z2, z3, do_swap);

    Fe z2_inv, res;
    fe_inv(z2_inv, z2);
    fe_mul(res, x2, z2_inv);
    fe_pack(shared_out, res);

    // Reject all-zero output (low-order peer public key) in constant time.
    u8 acc = 0u;
    for (usize i = 0u; i < 32u; ++i) acc |= shared_out[i];

    secure_zero(e, sizeof(e));
    secure_zero(&x2, sizeof(x2));
    secure_zero(&z2, sizeof(z2));
    secure_zero(&x3, sizeof(x3));
    secure_zero(&z3, sizeof(z3));
    return acc != 0u;
}

void x25519_public_key(const u8 private_key[32], u8 public_out[32]) noexcept {
    u8 base[32] = {};
    base[0] = 9u;
    (void)x25519(private_key, base, public_out);
}

// ---------------------------------------------------------------------------
// Ed25519 (RFC 8032)
// ---------------------------------------------------------------------------
void ed25519_public_key(const u8 seed[32], u8 public_out[32]) noexcept {
    StaticArray<u8, 64u> az = sha512(ArrayRef<u8>(seed, 32u));
    clamp_scalar(az.data());

    GePoint pub;
    ge_scalarmult_base(pub, az.data());
    ge_pack(public_out, pub);

    secure_zero(az.data(), az.size());
}

void ed25519_sign(const u8 seed[32], ArrayRef<u8> message, u8 signature_out[64]) noexcept {
    StaticArray<u8, 64u> az = sha512(ArrayRef<u8>(seed, 32u));
    clamp_scalar(az.data());

    // Derive public key A = [a]B.
    GePoint pub;
    ge_scalarmult_base(pub, az.data());
    u8 pub_bytes[32];
    ge_pack(pub_bytes, pub);

    // r = SHA-512(az[32..63] || message) mod L
    Sha512 h;
    h.update(az.data() + 32u, 32u);
    h.update(message);
    StaticArray<u8, 64u> r_hash = h.finalize();
    u8 r_sc[32];
    sc_reduce64(r_sc, r_hash.data());

    // R = [r]B -> signature_out[0..31]
    GePoint r_pt;
    ge_scalarmult_base(r_pt, r_sc);
    ge_pack(signature_out, r_pt);

    // k = SHA-512(R || A || message) mod L
    h.update(signature_out, 32u);
    h.update(pub_bytes, 32u);
    h.update(message);
    StaticArray<u8, 64u> k_hash = h.finalize();
    u8 k_sc[32];
    sc_reduce64(k_sc, k_hash.data());

    // S = (r + k * a) mod L -> signature_out[32..63]
    i64 x[64] = {};
    for (usize i = 0u; i < 32u; ++i) x[i] = as<i64>(r_sc[i]);
    for (usize i = 0u; i < 32u; ++i) {
        for (usize j = 0u; j < 32u; ++j) {
            x[i + j] += as<i64>(k_sc[i]) * as<i64>(az[j]);
        }
    }
    sc_mod_l(signature_out + 32u, x);

    secure_zero(az.data(), az.size());
    secure_zero(r_hash.data(), r_hash.size());
    secure_zero(k_hash.data(), k_hash.size());
    secure_zero(r_sc, sizeof(r_sc));
    secure_zero(k_sc, sizeof(k_sc));
    secure_zero(x, sizeof(x));
}

bool ed25519_verify(const u8 public_key[32], ArrayRef<u8> message,
                    const u8 signature[64]) noexcept {
    // Strict canonical S < L check (RFC 8032 §5.1.7).
    if (!le32_less(signature + 32u, kOrderL)) {
        return false;
    }

    // Validate canonical decoding of public key A (unpacked as -A) and R.
    GePoint neg_a;
    if (!ge_unpack_neg(neg_a, public_key)) {
        return false;
    }
    GePoint check_r_decode;
    if (!ge_unpack_neg(check_r_decode, signature)) {
        return false;
    }

    // k = SHA-512(R || A || message) mod L
    Sha512 h;
    h.update(signature, 32u);
    h.update(public_key, 32u);
    h.update(message);
    StaticArray<u8, 64u> k_hash = h.finalize();
    u8 k_sc[32];
    sc_reduce64(k_sc, k_hash.data());

    // Compute R' = [S]B + [k](-A) and verify encode(R') == R.
    GePoint sb;
    GePoint k_neg_a;
    GePoint r_calc;
    ge_scalarmult_base(sb, signature + 32u);
    ge_scalarmult(k_neg_a, neg_a, k_sc);
    ge_add(r_calc, sb, k_neg_a);

    u8 r_bytes[32];
    ge_pack(r_bytes, r_calc);
    return ct_equal(ArrayRef<u8>(r_bytes, 32u), ArrayRef<u8>(signature, 32u));
}

} // namespace keel::crypto
