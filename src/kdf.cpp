#include "keel/crypto/kdf.h"
#include "keel/crypto/ct.h"
#include "keel/crypto/hmac.h"

namespace keel::crypto {

Array<u8> hkdf_extract(DigestAlgorithm alg, ArrayRef<u8> salt, ArrayRef<u8> ikm, Allocator* alloc) {
    if (salt.empty()) {
        u8 zero_salt[kMaxDigestSize];
        const usize hash_len = digest_output_size(alg);
        for (usize i = 0u; i < hash_len; ++i) {
            zero_salt[i] = 0u;
        }
        return Hmac::compute(alg, ArrayRef<u8>(zero_salt, hash_len), ikm, alloc);
    }
    return Hmac::compute(alg, salt, ikm, alloc);
}

Optional<Array<u8>> hkdf_expand(
    DigestAlgorithm alg, ArrayRef<u8> prk, ArrayRef<u8> info, usize out_len, Allocator* alloc) {
    const usize hash_len = digest_output_size(alg);
    if (prk.size() < hash_len) return {};
    if (out_len > 255u * hash_len) return {};

    Array<u8> okm(alloc);
    okm.reserve(out_len);
    if (out_len == 0u) return okm;

    const usize n = (out_len + hash_len - 1u) / hash_len;
    u8 t_prev[kMaxDigestSize];
    usize t_len = 0u;

    Hmac mac(alg, prk);
    for (usize i = 1u; i <= n; ++i) {
        mac.reset();
        if (t_len > 0u) {
            mac.update(t_prev, t_len);
        }
        if (!info.empty()) {
            mac.update(info);
        }
        const u8 ctr = as<u8>(i);
        mac.update(&ctr, 1u);
        t_len = mac.finalize(MutArrayRef<u8>(t_prev, hash_len));

        const usize need = out_len - okm.size();
        const usize take = (need < t_len) ? need : t_len;
        for (usize j = 0u; j < take; ++j) {
            okm.push_back(t_prev[j]);
        }
    }

    secure_zero(t_prev, sizeof(t_prev));
    return okm;
}

Optional<Array<u8>> hkdf(
    DigestAlgorithm alg,
    ArrayRef<u8> salt,
    ArrayRef<u8> ikm,
    ArrayRef<u8> info,
    usize out_len,
    Allocator* alloc) {
    Array<u8> prk = hkdf_extract(alg, salt, ikm, alloc);
    auto out = hkdf_expand(alg, prk.as_ref(), info, out_len, alloc);
    secure_zero(prk.data(), prk.size());
    return out;
}

Optional<Array<u8>> pbkdf2_hmac(
    DigestAlgorithm alg,
    ArrayRef<u8> password,
    ArrayRef<u8> salt,
    u32 iterations,
    usize out_len,
    Allocator* alloc) {
    if (iterations == 0u) return {};

    Array<u8> dk(alloc);
    dk.reserve(out_len);
    if (out_len == 0u) return dk;

    const usize hash_len = digest_output_size(alg);
    const usize blocks = (out_len + hash_len - 1u) / hash_len;

    u8 u_buf[kMaxDigestSize];
    u8 t_buf[kMaxDigestSize];
    Hmac mac(alg, password);

    for (usize b = 1u; b <= blocks; ++b) {
        const u32 blk_idx = as<u32>(b);
        u8 idx_be[4] = {
            as<u8>((blk_idx >> 24u) & 0xFFu),
            as<u8>((blk_idx >> 16u) & 0xFFu),
            as<u8>((blk_idx >> 8u) & 0xFFu),
            as<u8>(blk_idx & 0xFFu),
        };

        mac.reset();
        if (!salt.empty()) mac.update(salt);
        mac.update(idx_be, 4u);
        (void)mac.finalize(MutArrayRef<u8>(u_buf, hash_len));

        for (usize j = 0u; j < hash_len; ++j) {
            t_buf[j] = u_buf[j];
        }

        for (u32 it = 1u; it < iterations; ++it) {
            mac.reset();
            mac.update(u_buf, hash_len);
            (void)mac.finalize(MutArrayRef<u8>(u_buf, hash_len));
            for (usize j = 0u; j < hash_len; ++j) {
                t_buf[j] = as<u8>(t_buf[j] ^ u_buf[j]);
            }
        }

        const usize need = out_len - dk.size();
        const usize take = (need < hash_len) ? need : hash_len;
        for (usize j = 0u; j < take; ++j) {
            dk.push_back(t_buf[j]);
        }
    }

    secure_zero(u_buf, sizeof(u_buf));
    secure_zero(t_buf, sizeof(t_buf));
    return dk;
}

} // namespace keel::crypto
