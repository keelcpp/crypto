#pragma once

#include "keel/array.h"
#include "keel/core.h"
#include "keel/optional.h"
#include "keel/ref.h"
#include "keel/static_array.h"

namespace keel::crypto {

inline constexpr usize kAesBlockSize = 16u;
inline constexpr usize kAes128KeySize = 16u;
inline constexpr usize kAes192KeySize = 24u;
inline constexpr usize kAes256KeySize = 32u;
inline constexpr usize kAesGcmTagSize = 16u;
inline constexpr usize kAesGcmDefaultNonceSize = 12u;

// ---------------------------------------------------------------------------
// Constant-time AES block cipher (FIPS-197: AES-128 / AES-192 / AES-256).
// Uses an algebraic GF(2^8) S-box (zero lookup tables -> cache-timing safe).
// Round keys are securely wiped on destruction.
// ---------------------------------------------------------------------------
class Aes {
public:
    Aes() noexcept = default;
    ~Aes() noexcept;

    Aes(const Aes&) = delete;
    Aes& operator=(const Aes&) = delete;
    Aes(Aes&& other) noexcept;
    Aes& operator=(Aes&& other) noexcept;

    // Initialize key schedule for a 16-, 24-, or 32-byte key.
    // Returns false if key.size() is not 16, 24, or 32.
    [[nodiscard]] bool init(ArrayRef<u8> key) noexcept;

    [[nodiscard]] bool valid() const noexcept { return m_rounds != 0u; }
    [[nodiscard]] usize rounds() const noexcept { return m_rounds; }

    // Encrypt / decrypt a single 16-byte block (in and out may alias).
    void encrypt_block(const u8 in[16], u8 out[16]) const noexcept;
    void decrypt_block(const u8 in[16], u8 out[16]) const noexcept;

private:
    u32 m_rk[60] = {};
    usize m_rounds = 0u;
};

// ---------------------------------------------------------------------------
// AES-CTR (NIST SP 800-38A): 128-bit big-endian counter increment.
// `in` and `out` may alias; returns false on invalid key size or mismatched lengths.
// ---------------------------------------------------------------------------
[[nodiscard]] bool aes_ctr_xor(ArrayRef<u8> key, const u8 iv[16], ArrayRef<u8> in,
                               MutArrayRef<u8> out) noexcept;

// ---------------------------------------------------------------------------
// AES-CBC (NIST SP 800-38A):
// - Raw block form: length must be a multiple of 16 bytes (no padding).
// - PKCS#7 form: adds/validates PKCS#7 padding in constant time.
// ---------------------------------------------------------------------------
[[nodiscard]] bool aes_cbc_encrypt_blocks(ArrayRef<u8> key, const u8 iv[16], ArrayRef<u8> in,
                                          MutArrayRef<u8> out) noexcept;
[[nodiscard]] bool aes_cbc_decrypt_blocks(ArrayRef<u8> key, const u8 iv[16], ArrayRef<u8> in,
                                          MutArrayRef<u8> out) noexcept;

[[nodiscard]] Optional<Array<u8>> aes_cbc_encrypt(ArrayRef<u8> key, const u8 iv[16],
                                                  ArrayRef<u8> plaintext,
                                                  Allocator* alloc = nullptr);
[[nodiscard]] Optional<Array<u8>> aes_cbc_decrypt(ArrayRef<u8> key, const u8 iv[16],
                                                  ArrayRef<u8> ciphertext,
                                                  Allocator* alloc = nullptr);

// ---------------------------------------------------------------------------
// AES-GCM AEAD (NIST SP 800-38D: AES-128-GCM / AES-192-GCM / AES-256-GCM).
// Supports arbitrary non-empty nonce lengths (12-byte fast path per spec).
// ---------------------------------------------------------------------------
[[nodiscard]] bool aes_gcm_encrypt(ArrayRef<u8> key, ArrayRef<u8> nonce, ArrayRef<u8> aad,
                                   ArrayRef<u8> plaintext, MutArrayRef<u8> ciphertext,
                                   u8 tag_out[16]) noexcept;

// Decrypts and verifies the 16-byte authentication tag in constant time.
// On authentication failure, `plaintext` is wiped with secure_zero and false is returned.
[[nodiscard]] bool aes_gcm_decrypt(ArrayRef<u8> key, ArrayRef<u8> nonce, ArrayRef<u8> aad,
                                   ArrayRef<u8> ciphertext, const u8 tag[16],
                                   MutArrayRef<u8> plaintext) noexcept;

} // namespace keel::crypto
