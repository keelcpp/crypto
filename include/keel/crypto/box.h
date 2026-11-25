#pragma once

#include "keel/array.h"
#include "keel/core.h"
#include "keel/optional.h"
#include "keel/ref.h"

namespace keel::crypto {

// ---------------------------------------------------------------------------
// Misuse-resistant high-level authenticated encryption APIs:
//
// 1. SecretBox (symmetric, 32-byte key):
//    Wire format: [24-byte random nonce || ciphertext || 16-byte Poly1305 tag]
//    Cipher: XChaCha20-Poly1305 (safe for random nonces).
//
// 2. SealedBox (anonymous public-key encryption to recipient X25519 pubkey):
//    Wire format: [32-byte ephemeral X25519 pubkey || ciphertext || 16-byte tag]
//    Key schedule: HKDF-SHA256(salt = ephem_pub || recipient_pub,
//                              ikm  = X25519(ephem_priv, recipient_pub),
//                              info = "keel-sealed-box-v1") -> (32B key || 24B nonce)
//    Cipher: XChaCha20-Poly1305.
// ---------------------------------------------------------------------------

inline constexpr usize kSecretBoxOverhead = 24u + 16u;
inline constexpr usize kSealedBoxOverhead = 32u + 16u;

[[nodiscard]] Optional<Array<u8>> secret_box_seal(const u8 key[32],
                                                  ArrayRef<u8> plaintext,
                                                  ArrayRef<u8> aad = {},
                                                  Allocator* alloc = nullptr);

[[nodiscard]] Optional<Array<u8>> secret_box_open(const u8 key[32],
                                                  ArrayRef<u8> sealed,
                                                  ArrayRef<u8> aad = {},
                                                  Allocator* alloc = nullptr);

[[nodiscard]] Optional<Array<u8>> sealed_box_seal(const u8 recipient_public[32],
                                                  ArrayRef<u8> plaintext,
                                                  ArrayRef<u8> aad = {},
                                                  Allocator* alloc = nullptr);

[[nodiscard]] Optional<Array<u8>> sealed_box_open(const u8 recipient_secret[32],
                                                  const u8 recipient_public[32],
                                                  ArrayRef<u8> sealed,
                                                  ArrayRef<u8> aad = {},
                                                  Allocator* alloc = nullptr);

} // namespace keel::crypto
