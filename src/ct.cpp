#include "keel/crypto/ct.h"

namespace keel::crypto {

void secure_zero(void* ptr, usize len) noexcept {
    if (!ptr || len == 0u) return;
    volatile u8* p = static_cast<volatile u8*>(ptr);
    for (usize i = 0u; i < len; ++i) {
        p[i] = 0u;
    }
}

bool ct_equal(const u8* a, const u8* b, usize len) noexcept {
    if (len == 0u) return true;
    if (!a || !b) return false;
    u8 diff = 0u;
    for (usize i = 0u; i < len; ++i) {
        diff |= as<u8>(a[i] ^ b[i]);
    }
    return diff == 0u;
}

String to_hex(ArrayRef<u8> bytes, bool uppercase, Allocator* alloc) {
    static constexpr char kLower[17] = "0123456789abcdef";
    static constexpr char kUpper[17] = "0123456789ABCDEF";
    const char* table = uppercase ? kUpper : kLower;

    String out(alloc);
    out.reserve(bytes.size() * 2u);
    for (usize i = 0u; i < bytes.size(); ++i) {
        const u8 b = bytes[i];
        out.push_back(table[as<usize>(b >> 4u)]);
        out.push_back(table[as<usize>(b & 0x0Fu)]);
    }
    return out;
}

namespace {

[[nodiscard]] constexpr i32 hex_nibble(char c) noexcept {
    if (c >= '0' && c <= '9') return as<i32>(c - '0');
    if (c >= 'a' && c <= 'f') return as<i32>(10 + (c - 'a'));
    if (c >= 'A' && c <= 'F') return as<i32>(10 + (c - 'A'));
    return -1;
}

} // namespace

Optional<Array<u8>> from_hex(StringRef hex, Allocator* alloc) {
    if ((hex.size() & 1u) != 0u) return {};
    Array<u8> out(alloc);
    out.reserve(hex.size() / 2u);
    for (usize i = 0u; i < hex.size(); i += 2u) {
        const i32 hi = hex_nibble(hex[i]);
        const i32 lo = hex_nibble(hex[i + 1u]);
        if (hi < 0 || lo < 0) return {};
        out.push_back(as<u8>((as<u32>(hi) << 4u) | as<u32>(lo)));
    }
    return out;
}

} // namespace keel::crypto
