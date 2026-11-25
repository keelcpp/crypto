#pragma once

#include "keel/array.h"
#include "keel/core.h"
#include "keel/optional.h"
#include "keel/ref.h"
#include "keel/string.h"

namespace keel::crypto {

// Overwrite sensitive memory so the compiler cannot optimize the wipe away.
void secure_zero(void* ptr, usize len) noexcept;

// Constant-time equality over two equal-length byte buffers.
// Returns false immediately only if sizes differ; compares all bytes otherwise.
[[nodiscard]] bool ct_equal(const u8* a, const u8* b, usize len) noexcept;
[[nodiscard]] inline bool ct_equal(ArrayRef<u8> a, ArrayRef<u8> b) noexcept {
    if (a.size() != b.size()) return false;
    return ct_equal(a.data(), b.data(), a.size());
}

// Constant-time select: mask == 0xFF returns a; mask == 0x00 returns b.
[[nodiscard]] constexpr u8 ct_select_u8(u8 mask, u8 a, u8 b) noexcept {
    return as<u8>((a & mask) | (b & as<u8>(~mask)));
}

// Constant-time select: mask == 0xFFFFFFFFu returns a; mask == 0u returns b.
[[nodiscard]] constexpr u32 ct_select_u32(u32 mask, u32 a, u32 b) noexcept {
    return (a & mask) | (b & ~mask);
}

// Encode bytes to lowercase (default) or uppercase hexadecimal string.
[[nodiscard]] String to_hex(ArrayRef<u8> bytes, bool uppercase = false, Allocator* alloc = nullptr);

// Decode hexadecimal string to bytes. Returns none on odd length or invalid hex characters.
[[nodiscard]] Optional<Array<u8>> from_hex(StringRef hex, Allocator* alloc = nullptr);

} // namespace keel::crypto
