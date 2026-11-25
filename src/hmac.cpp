#include "keel/crypto/hmac.h"
#include "keel/crypto/ct.h"

namespace keel::crypto {

Hmac::Hmac(DigestAlgorithm alg, ArrayRef<u8> key) noexcept
    : m_alg(alg), m_block_size(digest_block_size(alg)), m_inner(alg) {
    u8 key_block[kMaxDigestBlockSize];
    for (usize i = 0u; i < kMaxDigestBlockSize; ++i) {
        key_block[i] = 0u;
    }

    if (key.size() > m_block_size) {
        Digest kd(alg);
        kd.update(key);
        (void)kd.finalize(MutArrayRef<u8>(key_block, m_block_size));
    } else {
        for (usize i = 0u; i < key.size(); ++i) {
            key_block[i] = key[i];
        }
    }

    for (usize i = 0u; i < m_block_size; ++i) {
        m_ipad[i] = as<u8>(key_block[i] ^ 0x36u);
        m_opad[i] = as<u8>(key_block[i] ^ 0x5Cu);
    }
    secure_zero(key_block, sizeof(key_block));
    reset();
}

Hmac::~Hmac() noexcept {
    secure_zero(m_ipad, sizeof(m_ipad));
    secure_zero(m_opad, sizeof(m_opad));
}

void Hmac::reset() noexcept {
    m_inner.reset();
    m_inner.update(m_ipad, m_block_size);
}

void Hmac::update(const u8* data, usize len) noexcept { m_inner.update(data, len); }

usize Hmac::finalize(MutArrayRef<u8> out) noexcept {
    const usize sz = output_size();
    if (out.size() < sz) return 0u;

    u8 inner_hash[kMaxDigestSize];
    (void)m_inner.finalize(MutArrayRef<u8>(inner_hash, sz));

    Digest outer(m_alg);
    outer.update(m_opad, m_block_size);
    outer.update(inner_hash, sz);
    const usize written = outer.finalize(out);

    secure_zero(inner_hash, sizeof(inner_hash));
    reset();
    return written;
}

Array<u8> Hmac::finalize(Allocator* alloc) {
    Array<u8> out(alloc);
    out.resize(output_size());
    (void)finalize(out.as_mut_ref());
    return out;
}

Array<u8> Hmac::compute(DigestAlgorithm alg, ArrayRef<u8> key, ArrayRef<u8> data, Allocator* alloc) {
    Hmac h(alg, key);
    h.update(data);
    return h.finalize(alloc);
}

bool Hmac::verify(DigestAlgorithm alg, ArrayRef<u8> key, ArrayRef<u8> data, ArrayRef<u8> expected_tag) noexcept {
    const usize sz = digest_output_size(alg);
    if (expected_tag.size() != sz) return false;
    u8 computed[kMaxDigestSize];
    Hmac h(alg, key);
    h.update(data);
    (void)h.finalize(MutArrayRef<u8>(computed, sz));
    const bool ok = ct_equal(computed, expected_tag.data(), sz);
    secure_zero(computed, sizeof(computed));
    return ok;
}

} // namespace keel::crypto
