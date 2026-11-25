#pragma once

#include "keel/core.h"
#include "keel/ref.h"

namespace keel::crypto {

inline constexpr usize kX25519KeySize = 32u;
inline constexpr usize kEd25519SeedSize = 32u;
inline constexpr usize kEd25519PublicKeySize = 32u;
inline constexpr usize kEd25519SignatureSize = 64u;

// ---------------------------------------------------------------------------
// X25519 Diffie-Hellman key agreement (RFC 7748)
// Constant-time Montgomery ladder over GF(2^255 - 19).
// ---------------------------------------------------------------------------

// Computes shared secret = X25519(scalar, peer_public).
// Returns false if the resulting shared secret is all zeros (low-order input).
[[nodiscard]] bool x25519(const u8 scalar[32], const u8 peer_public[32],
                          u8 shared_out[32]) noexcept;

// Derives the 32-byte X25519 public key from a 32-byte private key (basepoint u = 9).
void x25519_public_key(const u8 private_key[32], u8 public_out[32]) noexcept;

// ---------------------------------------------------------------------------
// Ed25519 digital signatures (RFC 8032 — PureEdDSA over Edwards25519)
// Deterministic signing using SHA-512; strict canonical S < L verification.
// ---------------------------------------------------------------------------

// Derives the 32-byte Ed25519 public key from a 32-byte secret seed.
void ed25519_public_key(const u8 seed[32], u8 public_out[32]) noexcept;

// Signs `message` deterministically with `seed` (32 bytes), writing a 64-byte signature.
void ed25519_sign(const u8 seed[32], ArrayRef<u8> message, u8 signature_out[64]) noexcept;

// Verifies a 64-byte Ed25519 `signature` over `message` under `public_key`.
// Enforces canonical point encoding (y < p) and canonical scalar (S < L).
[[nodiscard]] bool ed25519_verify(const u8 public_key[32], ArrayRef<u8> message,
                                  const u8 signature[64]) noexcept;

} // namespace keel::crypto
