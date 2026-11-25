#pragma once

#include "keel/core.h"
#include "keel/ref.h"
#include "keel/static_array.h"

namespace keel::crypto {

inline constexpr usize kChaCha20KeySize = 32u;
inline constexpr usize kChaCha20NonceSize = 12u;
inline constexpr usize kXChaCha20NonceSize = 24u;
inline constexpr usize kChaCha20BlockSize = 64u;
inline constexpr usize kPoly1305KeySize = 32u;
inline constexpr usize kPoly1305TagSize = 16u;

// ---------------------------------------------------------------------------
// ChaCha20 (RFC 8439) & HChaCha20 (draft-irtf-cfrg-xchacha)
// ---------------------------------------------------------------------------
void chacha20_block(const u8 key[32], u32 counter, const u8 nonce[12], u8 out[64]) noexcept;

// XORs `in` with ChaCha20 keystream starting at `counter` into `out` (in and out may alias).
// Returns false if in.size() != out.size().
[[nodiscard]] bool chacha20_xor(const u8 key[32], u32 counter, const u8 nonce[12],
                                ArrayRef<u8> in, MutArrayRef<u8> out) noexcept;

// HChaCha20 subkey derivation (32-byte key + 16-byte nonce -> 32-byte subkey).
void hchacha20(const u8 key[32], const u8 nonce[16], u8 out[32]) noexcept;

// ---------------------------------------------------------------------------
// Poly1305 one-time authenticator (RFC 8439) — 26-bit limb constant-time impl
// ---------------------------------------------------------------------------
class Poly1305 {
public:
    static constexpr usize kKeySize = 32u;
    static constexpr usize kTagSize = 16u;

    Poly1305() noexcept = default;
    explicit Poly1305(const u8 key[32]) noexcept { init(key); }
    ~Poly1305() noexcept;

    Poly1305(const Poly1305&) = delete;
    Poly1305& operator=(const Poly1305&) = delete;

    void init(const u8 key[32]) noexcept;
    void update(const u8* data, usize len) noexcept;
    void update(ArrayRef<u8> data) noexcept { update(data.data(), data.size()); }
    void finalize(u8 tag_out[16]) noexcept;
    [[nodiscard]] StaticArray<u8, 16u> finalize() noexcept;

    [[nodiscard]] static StaticArray<u8, 16u> mac(const u8 key[32], ArrayRef<u8> msg) noexcept;

private:
    void process_block(const u8 block[16], bool is_final, usize len) noexcept;

    u32 m_r[5] = {};
    u32 m_h[5] = {};
    u32 m_pad[4] = {};
    u8 m_buf[16] = {};
    usize m_buf_len = 0u;
};

// ---------------------------------------------------------------------------
// ChaCha20-Poly1305 AEAD (RFC 8439 §2.8)
// ---------------------------------------------------------------------------
[[nodiscard]] bool chacha20_poly1305_encrypt(const u8 key[32], const u8 nonce[12],
                                             ArrayRef<u8> aad, ArrayRef<u8> plaintext,
                                             MutArrayRef<u8> ciphertext,
                                             u8 tag_out[16]) noexcept;

// Decrypts and verifies the 16-byte tag in constant time.
// Wipes `plaintext` with secure_zero and returns false on authentication failure.
[[nodiscard]] bool chacha20_poly1305_decrypt(const u8 key[32], const u8 nonce[12],
                                             ArrayRef<u8> aad, ArrayRef<u8> ciphertext,
                                             const u8 tag[16],
                                             MutArrayRef<u8> plaintext) noexcept;

// ---------------------------------------------------------------------------
// XChaCha20-Poly1305 AEAD (24-byte extended nonce via HChaCha20)
// ---------------------------------------------------------------------------
[[nodiscard]] bool xchacha20_poly1305_encrypt(const u8 key[32], const u8 nonce[24],
                                              ArrayRef<u8> aad, ArrayRef<u8> plaintext,
                                              MutArrayRef<u8> ciphertext,
                                              u8 tag_out[16]) noexcept;

[[nodiscard]] bool xchacha20_poly1305_decrypt(const u8 key[32], const u8 nonce[24],
                                              ArrayRef<u8> aad, ArrayRef<u8> ciphertext,
                                              const u8 tag[16],
                                              MutArrayRef<u8> plaintext) noexcept;

} // namespace keel::crypto
