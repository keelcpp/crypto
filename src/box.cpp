#include "keel/crypto/box.h"

#include "keel/crypto/chacha20.h"
#include "keel/crypto/ct.h"
#include "keel/crypto/curve25519.h"
#include "keel/crypto/kdf.h"
#include "keel/crypto/random.h"
#include "keel/memory.h"

namespace keel::crypto {

namespace {

constexpr StringRef kSealedBoxInfo = "keel-sealed-box-v1";

bool derive_sealed_box_keys(const u8 ephem_pub[32], const u8 recipient_pub[32],
                            const u8 shared[32], u8 key_out[32], u8 nonce_out[24]) noexcept {
    u8 salt[64];
    mem_copy(salt, ephem_pub, 32u);
    mem_copy(salt + 32u, recipient_pub, 32u);
    const ArrayRef<u8> info_ref(reinterpret_cast<const u8*>(kSealedBoxInfo.data()),
                                kSealedBoxInfo.size());
    auto okm = hkdf(DigestAlgorithm::Sha256, ArrayRef<u8>(salt, 64u),
                    ArrayRef<u8>(shared, 32u), info_ref, 56u);
    const bool ok = okm.has_value() && okm->size() == 56u;
    if (ok) {
        mem_copy(key_out, okm->data(), 32u);
        mem_copy(nonce_out, okm->data() + 32u, 24u);
    }
    secure_zero(salt, sizeof(salt));
    if (okm.has_value()) secure_zero(okm->data(), okm->size());
    return ok;
}

} // namespace

Optional<Array<u8>> secret_box_seal(const u8 key[32], ArrayRef<u8> plaintext,
                                    ArrayRef<u8> aad, Allocator* alloc) {
    if (!key || plaintext.size() > Limits<usize>::kMax - kSecretBoxOverhead) {
        return Optional<Array<u8>>{};
    }
    u8 nonce[24];
    if (!random_bytes(nonce, 24u)) return Optional<Array<u8>>{};

    Array<u8> out(kSecretBoxOverhead + plaintext.size(), u8{0u}, alloc);
    mem_copy(out.data(), nonce, 24u);
    MutArrayRef<u8> ct(out.data() + 24u, plaintext.size());
    u8* tag = out.data() + 24u + plaintext.size();

    const bool ok = xchacha20_poly1305_encrypt(key, nonce, aad, plaintext, ct, tag);
    secure_zero(nonce, sizeof(nonce));
    if (!ok) {
        secure_zero(out.data(), out.size());
        return Optional<Array<u8>>{};
    }
    return out;
}

Optional<Array<u8>> secret_box_open(const u8 key[32], ArrayRef<u8> sealed,
                                    ArrayRef<u8> aad, Allocator* alloc) {
    if (!key || sealed.size() < kSecretBoxOverhead) return Optional<Array<u8>>{};
    const usize pt_len = sealed.size() - kSecretBoxOverhead;
    const u8* nonce = sealed.data();
    const ArrayRef<u8> ct(sealed.data() + 24u, pt_len);
    const u8* tag = sealed.data() + 24u + pt_len;

    Array<u8> pt(pt_len, u8{0u}, alloc);
    if (!xchacha20_poly1305_decrypt(key, nonce, aad, ct, tag, pt.as_mut_ref())) {
        secure_zero(pt.data(), pt.size());
        return Optional<Array<u8>>{};
    }
    return pt;
}

Optional<Array<u8>> sealed_box_seal(const u8 recipient_public[32], ArrayRef<u8> plaintext,
                                    ArrayRef<u8> aad, Allocator* alloc) {
    if (!recipient_public || plaintext.size() > Limits<usize>::kMax - kSealedBoxOverhead) {
        return Optional<Array<u8>>{};
    }
    auto ephem = generate_x25519_keypair();
    if (!ephem.has_value()) return Optional<Array<u8>>{};

    u8 shared[32];
    if (!x25519(ephem->secret_key.data(), recipient_public, shared)) {
        secure_zero(shared, sizeof(shared));
        return Optional<Array<u8>>{};
    }

    u8 sym_key[32];
    u8 nonce[24];
    const bool derived = derive_sealed_box_keys(ephem->public_key.data(), recipient_public,
                                                shared, sym_key, nonce);
    secure_zero(shared, sizeof(shared));
    if (!derived) {
        secure_zero(sym_key, sizeof(sym_key));
        secure_zero(nonce, sizeof(nonce));
        return Optional<Array<u8>>{};
    }

    Array<u8> out(kSealedBoxOverhead + plaintext.size(), u8{0u}, alloc);
    mem_copy(out.data(), ephem->public_key.data(), 32u);
    MutArrayRef<u8> ct(out.data() + 32u, plaintext.size());
    u8* tag = out.data() + 32u + plaintext.size();

    const bool ok = xchacha20_poly1305_encrypt(sym_key, nonce, aad, plaintext, ct, tag);
    secure_zero(sym_key, sizeof(sym_key));
    secure_zero(nonce, sizeof(nonce));
    if (!ok) {
        secure_zero(out.data(), out.size());
        return Optional<Array<u8>>{};
    }
    return out;
}

Optional<Array<u8>> sealed_box_open(const u8 recipient_secret[32], const u8 recipient_public[32],
                                    ArrayRef<u8> sealed, ArrayRef<u8> aad, Allocator* alloc) {
    if (!recipient_secret || !recipient_public || sealed.size() < kSealedBoxOverhead) {
        return Optional<Array<u8>>{};
    }
    const u8* ephem_pub = sealed.data();
    const usize pt_len = sealed.size() - kSealedBoxOverhead;
    const ArrayRef<u8> ct(sealed.data() + 32u, pt_len);
    const u8* tag = sealed.data() + 32u + pt_len;

    u8 shared[32];
    if (!x25519(recipient_secret, ephem_pub, shared)) {
        secure_zero(shared, sizeof(shared));
        return Optional<Array<u8>>{};
    }

    u8 sym_key[32];
    u8 nonce[24];
    const bool derived = derive_sealed_box_keys(ephem_pub, recipient_public, shared, sym_key, nonce);
    secure_zero(shared, sizeof(shared));
    if (!derived) {
        secure_zero(sym_key, sizeof(sym_key));
        secure_zero(nonce, sizeof(nonce));
        return Optional<Array<u8>>{};
    }

    Array<u8> pt(pt_len, u8{0u}, alloc);
    const bool ok = xchacha20_poly1305_decrypt(sym_key, nonce, aad, ct, tag, pt.as_mut_ref());
    secure_zero(sym_key, sizeof(sym_key));
    secure_zero(nonce, sizeof(nonce));
    if (!ok) {
        secure_zero(pt.data(), pt.size());
        return Optional<Array<u8>>{};
    }
    return pt;
}

} // namespace keel::crypto
