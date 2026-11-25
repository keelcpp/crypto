#include "keel/crypto/digest.h"
#include "keel/crypto/ct.h"

#include <new>

namespace keel::crypto {

namespace {

[[nodiscard]] constexpr u32 rotl32(u32 x, u32 n) noexcept {
    return (x << n) | (x >> (32u - n));
}

[[nodiscard]] constexpr u32 rotr32(u32 x, u32 n) noexcept {
    return (x >> n) | (x << (32u - n));
}

[[nodiscard]] constexpr u64 rotr64(u64 x, u32 n) noexcept {
    return (x >> n) | (x << (64u - n));
}

[[nodiscard]] constexpr u32 load_le32(const u8* p) noexcept {
    return as<u32>(p[0]) | (as<u32>(p[1]) << 8u) | (as<u32>(p[2]) << 16u) |
           (as<u32>(p[3]) << 24u);
}

constexpr void store_le32(u8* p, u32 v) noexcept {
    p[0] = as<u8>(v & 0xFFu);
    p[1] = as<u8>((v >> 8u) & 0xFFu);
    p[2] = as<u8>((v >> 16u) & 0xFFu);
    p[3] = as<u8>((v >> 24u) & 0xFFu);
}

constexpr void store_le64(u8* p, u64 v) noexcept {
    for (usize i = 0u; i < 8u; ++i) {
        p[i] = as<u8>((v >> (i * 8u)) & 0xFFu);
    }
}

[[nodiscard]] constexpr u32 load_be32(const u8* p) noexcept {
    return (as<u32>(p[0]) << 24u) | (as<u32>(p[1]) << 16u) | (as<u32>(p[2]) << 8u) |
           as<u32>(p[3]);
}

constexpr void store_be32(u8* p, u32 v) noexcept {
    p[0] = as<u8>((v >> 24u) & 0xFFu);
    p[1] = as<u8>((v >> 16u) & 0xFFu);
    p[2] = as<u8>((v >> 8u) & 0xFFu);
    p[3] = as<u8>(v & 0xFFu);
}

[[nodiscard]] constexpr u64 load_be64(const u8* p) noexcept {
    return (as<u64>(p[0]) << 56u) | (as<u64>(p[1]) << 48u) | (as<u64>(p[2]) << 40u) |
           (as<u64>(p[3]) << 32u) | (as<u64>(p[4]) << 24u) | (as<u64>(p[5]) << 16u) |
           (as<u64>(p[6]) << 8u) | as<u64>(p[7]);
}

constexpr void store_be64(u8* p, u64 v) noexcept {
    for (usize i = 0u; i < 8u; ++i) {
        p[7u - i] = as<u8>((v >> (i * 8u)) & 0xFFu);
    }
}

constexpr void copy_bytes(u8* dst, const u8* src, usize n) noexcept {
    for (usize i = 0u; i < n; ++i) {
        dst[i] = src[i];
    }
}

constexpr void zero_bytes(u8* dst, usize n) noexcept {
    for (usize i = 0u; i < n; ++i) {
        dst[i] = 0u;
    }
}

[[nodiscard]] constexpr bool eq_ascii_ci(StringRef a, StringRef b) noexcept {
    if (a.size() != b.size()) return false;
    for (usize i = 0u; i < a.size(); ++i) {
        char ca = a[i];
        char cb = b[i];
        if (ca >= 'a' && ca <= 'z') ca = as<char>(ca - ('a' - 'A'));
        if (cb >= 'a' && cb <= 'z') cb = as<char>(cb - ('a' - 'A'));
        if (ca != cb) return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Algorithm constants
// ---------------------------------------------------------------------------

// RFC 1319 Pi substitution table (256 bytes)
inline constexpr u8 kMd2Pi[256] = {
    41u,  46u,  67u,  201u, 162u, 216u, 124u, 1u,   61u,  54u,  84u,  161u, 236u, 240u, 6u,   19u,
    98u,  167u, 5u,   243u, 192u, 199u, 115u, 140u, 152u, 147u, 43u,  217u, 188u, 76u,  130u, 202u,
    30u,  155u, 87u,  60u,  253u, 212u, 224u, 22u,  103u, 66u,  111u, 24u,  138u, 23u,  229u, 18u,
    190u, 78u,  196u, 214u, 218u, 158u, 222u, 73u,  160u, 251u, 245u, 142u, 187u, 47u,  238u, 122u,
    169u, 104u, 121u, 145u, 21u,  178u, 7u,   63u,  148u, 194u, 16u,  137u, 11u,  34u,  95u,  33u,
    128u, 127u, 93u,  154u, 90u,  144u, 50u,  39u,  53u,  62u,  204u, 231u, 191u, 247u, 151u, 3u,
    255u, 25u,  48u,  179u, 72u,  165u, 181u, 209u, 215u, 94u,  146u, 42u,  172u, 86u,  170u, 198u,
    79u,  184u, 56u,  210u, 150u, 164u, 125u, 182u, 118u, 252u, 107u, 226u, 156u, 116u, 4u,   241u,
    69u,  157u, 112u, 89u,  100u, 113u, 135u, 32u,  134u, 91u,  207u, 101u, 230u, 45u,  168u, 2u,
    27u,  96u,  37u,  173u, 174u, 176u, 185u, 246u, 28u,  70u,  97u,  105u, 52u,  64u,  126u, 15u,
    85u,  71u,  163u, 35u,  221u, 81u,  175u, 58u,  195u, 92u,  249u, 206u, 186u, 197u, 234u, 38u,
    44u,  83u,  13u,  110u, 133u, 40u,  132u, 9u,   211u, 223u, 205u, 244u, 65u,  129u, 77u,  82u,
    106u, 220u, 55u,  200u, 108u, 193u, 171u, 250u, 36u,  225u, 123u, 8u,   12u,  189u, 177u, 74u,
    120u, 136u, 149u, 139u, 227u, 99u,  232u, 109u, 233u, 203u, 213u, 254u, 59u,  0u,   29u,  57u,
    242u, 239u, 183u, 14u,  102u, 88u,  208u, 228u, 166u, 119u, 114u, 248u, 235u, 117u, 75u,  10u,
    49u,  68u,  80u,  180u, 143u, 237u, 31u,  26u,  219u, 153u, 141u, 51u,  159u, 17u,  131u, 20u,
};

// RFC 1321 MD5 constants
inline constexpr u32 kMd5K[64] = {
    0xD76AA478u, 0xE8C7B756u, 0x242070DBu, 0xC1BDCEEEu, 0xF57C0FAFu, 0x4787C62Au, 0xA8304613u, 0xFD469501u,
    0x698098D8u, 0x8B44F7AFu, 0xFFFF5BB1u, 0x895CD7BEu, 0x6B901122u, 0xFD987193u, 0xA679438Eu, 0x49B40821u,
    0xF61E2562u, 0xC040B340u, 0x265E5A51u, 0xE9B6C7AAu, 0xD62F105Du, 0x02441453u, 0xD8A1E681u, 0xE7D3FBC8u,
    0x21E1CDE6u, 0xC33707D6u, 0xF4D50D87u, 0x455A14EDu, 0xA9E3E905u, 0xFCEFA3F8u, 0x676F02D9u, 0x8D2A4C8Au,
    0xFFFA3942u, 0x8771F681u, 0x6D9D6122u, 0xFDE5380Cu, 0xA4BEEA44u, 0x4BDECFA9u, 0xF6BB4B60u, 0xBEBFBC70u,
    0x289B7EC6u, 0xEAA127FAu, 0xD4EF3085u, 0x04881D05u, 0xD9D4D039u, 0xE6DB99E5u, 0x1FA27CF8u, 0xC4AC5665u,
    0xF4292244u, 0x432AFF97u, 0xAB9423A7u, 0xFC93A039u, 0x655B59C3u, 0x8F0CCC92u, 0xFFEFF47Du, 0x85845DD1u,
    0x6FA87E4Fu, 0xFE2CE6E0u, 0xA3014314u, 0x4E0811A1u, 0xF7537E82u, 0xBD3AF235u, 0x2AD7D2BBu, 0xEB86D391u,
};

inline constexpr u32 kMd5Shift[64] = {
    7u, 12u, 17u, 22u, 7u, 12u, 17u, 22u, 7u, 12u, 17u, 22u, 7u, 12u, 17u, 22u,
    5u,  9u, 14u, 20u, 5u,  9u, 14u, 20u, 5u,  9u, 14u, 20u, 5u,  9u, 14u, 20u,
    4u, 11u, 16u, 23u, 4u, 11u, 16u, 23u, 4u, 11u, 16u, 23u, 4u, 11u, 16u, 23u,
    6u, 10u, 15u, 21u, 6u, 10u, 15u, 21u, 6u, 10u, 15u, 21u, 6u, 10u, 15u, 21u,
};

// FIPS 180-4 SHA-256 / SHA-224
inline constexpr u32 kSha256Iv[8] = {
    0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u, 0xA54FF53Au,
    0x510E527Fu, 0x9B05688Cu, 0x1F83D9ABu, 0x5BE0CD19u,
};

inline constexpr u32 kSha224Iv[8] = {
    0xC1059ED8u, 0x367CD507u, 0x3070DD17u, 0xF70E5939u,
    0xFFC00B31u, 0x68581511u, 0x64F98FA7u, 0xBEFA4FA4u,
};

inline constexpr u32 kSha256K[64] = {
    0x428A2F98u, 0x71374491u, 0xB5C0FBCFu, 0xE9B5DBA5u, 0x3956C25Bu, 0x59F111F1u, 0x923F82A4u, 0xAB1C5ED5u,
    0xD807AA98u, 0x12835B01u, 0x243185BEu, 0x550C7DC3u, 0x72BE5D74u, 0x80DEB1FEu, 0x9BDC06A7u, 0xC19BF174u,
    0xE49B69C1u, 0xEFBE4786u, 0x0FC19DC6u, 0x240CA1CCu, 0x2DE92C6Fu, 0x4A7484AAu, 0x5CB0A9DCu, 0x76F988DAu,
    0x983E5152u, 0xA831C66Du, 0xB00327C8u, 0xBF597FC7u, 0xC6E00BF3u, 0xD5A79147u, 0x06CA6351u, 0x14292967u,
    0x27B70A85u, 0x2E1B2138u, 0x4D2C6DFCu, 0x53380D13u, 0x650A7354u, 0x766A0ABBu, 0x81C2C92Eu, 0x92722C85u,
    0xA2BFE8A1u, 0xA81A664Bu, 0xC24B8B70u, 0xC76C51A3u, 0xD192E819u, 0xD6990624u, 0xF40E3585u, 0x106AA070u,
    0x19A4C116u, 0x1E376C08u, 0x2748774Cu, 0x34B0BCB5u, 0x391C0CB3u, 0x4ED8AA4Au, 0x5B9CCA4Fu, 0x682E6FF3u,
    0x748F82EEu, 0x78A5636Fu, 0x84C87814u, 0x8CC70208u, 0x90BEFFFAu, 0xA4506CEBu, 0xBEF9A3F7u, 0xC67178F2u,
};

// FIPS 180-4 SHA-512 / SHA-384
inline constexpr u64 kSha512Iv[8] = {
    0x6A09E667F3BCC908ULL, 0xBB67AE8584CAA73BULL, 0x3C6EF372FE94F82BULL, 0xA54FF53A5F1D36F1ULL,
    0x510E527FADE682D1ULL, 0x9B05688C2B3E6C1FULL, 0x1F83D9ABFB41BD6BULL, 0x5BE0CD19137E2179ULL,
};

inline constexpr u64 kSha384Iv[8] = {
    0xCBBB9D5DC1059ED8ULL, 0x629A292A367CD507ULL, 0x9159015A3070DD17ULL, 0x152FECD8F70E5939ULL,
    0x67332667FFC00B31ULL, 0x8EB44A8768581511ULL, 0xDB0C2E0D64F98FA7ULL, 0x47B5481DBEFA4FA4ULL,
};

inline constexpr u64 kSha512K[80] = {
    0x428A2F98D728AE22ULL, 0x7137449123EF65CDULL, 0xB5C0FBCFEC4D3B2FULL, 0xE9B5DBA58189DBBCULL,
    0x3956C25BF348B538ULL, 0x59F111F1B605D019ULL, 0x923F82A4AF194F9BULL, 0xAB1C5ED5DA6D8118ULL,
    0xD807AA98A3030242ULL, 0x12835B0145706FBEULL, 0x243185BE4EE4B28CULL, 0x550C7DC3D5FFB4E2ULL,
    0x72BE5D74F27B896FULL, 0x80DEB1FE3B1696B1ULL, 0x9BDC06A725C71235ULL, 0xC19BF174CF692694ULL,
    0xE49B69C19EF14AD2ULL, 0xEFBE4786384F25E3ULL, 0x0FC19DC68B8CD5B5ULL, 0x240CA1CC77AC9C65ULL,
    0x2DE92C6F592B0275ULL, 0x4A7484AA6EA6E483ULL, 0x5CB0A9DCBD41FBD4ULL, 0x76F988DA831153B5ULL,
    0x983E5152EE66DFABULL, 0xA831C66D2DB43210ULL, 0xB00327C898FB213FULL, 0xBF597FC7BEEF0EE4ULL,
    0xC6E00BF33DA88FC2ULL, 0xD5A79147930AA725ULL, 0x06CA6351E003826FULL, 0x142929670A0E6E70ULL,
    0x27B70A8546D22FFCULL, 0x2E1B21385C26C926ULL, 0x4D2C6DFC5AC42AEDULL, 0x53380D139D95B3DFULL,
    0x650A73548BAF63DEULL, 0x766A0ABB3C77B2A8ULL, 0x81C2C92E47EDAEE6ULL, 0x92722C851482353BULL,
    0xA2BFE8A14CF10364ULL, 0xA81A664BBC423001ULL, 0xC24B8B70D0F89791ULL, 0xC76C51A30654BE30ULL,
    0xD192E819D6EF5218ULL, 0xD69906245565A910ULL, 0xF40E35855771202AULL, 0x106AA07032BBD1B8ULL,
    0x19A4C116B8D2D0C8ULL, 0x1E376C085141AB53ULL, 0x2748774CDF8EEB99ULL, 0x34B0BCB5E19B48A8ULL,
    0x391C0CB3C5C95A63ULL, 0x4ED8AA4AE3418ACBULL, 0x5B9CCA4F7763E373ULL, 0x682E6FF3D6B2B8A3ULL,
    0x748F82EE5DEFB2FCULL, 0x78A5636F43172F60ULL, 0x84C87814A1F0AB72ULL, 0x8CC702081A6439ECULL,
    0x90BEFFFA23631E28ULL, 0xA4506CEBDE82BDE9ULL, 0xBEF9A3F7B2C67915ULL, 0xC67178F2E372532BULL,
    0xCA273ECEEA26619CULL, 0xD186B8C721C0C207ULL, 0xEADA7DD6CDE0EB1EULL, 0xF57D4F7FEE6ED178ULL,
    0x06F067AA72176FBAULL, 0x0A637DC5A2C898A6ULL, 0x113F9804BEF90DAEULL, 0x1B710B35131C471BULL,
    0x28DB77F523047D84ULL, 0x32CAAB7B40C72493ULL, 0x3C9EBE0A15C9BEBCULL, 0x431D67C49C100D4CULL,
    0x4CC5D4BECB3E42B6ULL, 0x597F299CFC657E2AULL, 0x5FCB6FAB3AD6FAECULL, 0x6C44198C4A475817ULL,
};

} // namespace

// ---------------------------------------------------------------------------
// Algorithm metadata
// ---------------------------------------------------------------------------

Optional<DigestAlgorithm> parse_digest_algorithm(StringRef name) noexcept {
    if (eq_ascii_ci(name, "MD2")) return DigestAlgorithm::Md2;
    if (eq_ascii_ci(name, "MD5")) return DigestAlgorithm::Md5;
    if (eq_ascii_ci(name, "SHA-1") || eq_ascii_ci(name, "SHA1") || eq_ascii_ci(name, "SHA")) {
        return DigestAlgorithm::Sha1;
    }
    if (eq_ascii_ci(name, "SHA-224") || eq_ascii_ci(name, "SHA224")) return DigestAlgorithm::Sha224;
    if (eq_ascii_ci(name, "SHA-256") || eq_ascii_ci(name, "SHA256")) return DigestAlgorithm::Sha256;
    if (eq_ascii_ci(name, "SHA-384") || eq_ascii_ci(name, "SHA384")) return DigestAlgorithm::Sha384;
    if (eq_ascii_ci(name, "SHA-512") || eq_ascii_ci(name, "SHA512")) return DigestAlgorithm::Sha512;
    return {};
}

StringRef digest_algorithm_name(DigestAlgorithm alg) noexcept {
    switch (alg) {
        case DigestAlgorithm::Md2: return "MD2";
        case DigestAlgorithm::Md5: return "MD5";
        case DigestAlgorithm::Sha1: return "SHA-1";
        case DigestAlgorithm::Sha224: return "SHA-224";
        case DigestAlgorithm::Sha256: return "SHA-256";
        case DigestAlgorithm::Sha384: return "SHA-384";
        case DigestAlgorithm::Sha512: return "SHA-512";
    }
    return "SHA-256";
}

usize digest_output_size(DigestAlgorithm alg) noexcept {
    switch (alg) {
        case DigestAlgorithm::Md2: return Md2::kDigestSize;
        case DigestAlgorithm::Md5: return Md5::kDigestSize;
        case DigestAlgorithm::Sha1: return Sha1::kDigestSize;
        case DigestAlgorithm::Sha224: return Sha224::kDigestSize;
        case DigestAlgorithm::Sha256: return Sha256::kDigestSize;
        case DigestAlgorithm::Sha384: return Sha384::kDigestSize;
        case DigestAlgorithm::Sha512: return Sha512::kDigestSize;
    }
    return Sha256::kDigestSize;
}

usize digest_block_size(DigestAlgorithm alg) noexcept {
    switch (alg) {
        case DigestAlgorithm::Md2: return Md2::kBlockSize;
        case DigestAlgorithm::Md5: return Md5::kBlockSize;
        case DigestAlgorithm::Sha1: return Sha1::kBlockSize;
        case DigestAlgorithm::Sha224: return Sha224::kBlockSize;
        case DigestAlgorithm::Sha256: return Sha256::kBlockSize;
        case DigestAlgorithm::Sha384: return Sha384::kBlockSize;
        case DigestAlgorithm::Sha512: return Sha512::kBlockSize;
    }
    return Sha256::kBlockSize;
}

// ---------------------------------------------------------------------------
// MD2 (RFC 1319)
// ---------------------------------------------------------------------------

Md2::Md2() noexcept { reset(); }

Md2::~Md2() noexcept {
    secure_zero(m_state, sizeof(m_state));
    secure_zero(m_checksum, sizeof(m_checksum));
    secure_zero(m_buf, sizeof(m_buf));
    m_buf_len = 0u;
}

void Md2::reset() noexcept {
    zero_bytes(m_state, sizeof(m_state));
    zero_bytes(m_checksum, sizeof(m_checksum));
    zero_bytes(m_buf, sizeof(m_buf));
    m_buf_len = 0u;
}

void Md2::transform(const u8 block[16]) noexcept {
    for (usize j = 0u; j < 16u; ++j) {
        m_state[16u + j] = block[j];
        m_state[32u + j] = as<u8>(m_state[16u + j] ^ m_state[j]);
    }
    u8 t = 0u;
    for (usize j = 0u; j < 18u; ++j) {
        for (usize k = 0u; k < 48u; ++k) {
            t = as<u8>(m_state[k] ^ kMd2Pi[as<usize>(t)]);
            m_state[k] = t;
        }
        t = as<u8>((as<u32>(t) + as<u32>(j)) & 0xFFu);
    }
}

void Md2::update(const u8* data, usize len) noexcept {
    if (!data || len == 0u) return;
    usize offset = 0u;
    while (offset < len) {
        const usize take = (len - offset < 16u - m_buf_len) ? (len - offset) : (16u - m_buf_len);
        copy_bytes(m_buf + m_buf_len, data + offset, take);
        m_buf_len += take;
        offset += take;
        if (m_buf_len == 16u) {
            u8 l = m_checksum[15];
            for (usize j = 0u; j < 16u; ++j) {
                const u8 c = m_buf[j];
                l = as<u8>(m_checksum[j] ^ kMd2Pi[as<usize>(c ^ l)]);
                m_checksum[j] = l;
            }
            transform(m_buf);
            m_buf_len = 0u;
        }
    }
}

void Md2::finalize(u8* out) noexcept {
    const u8 pad = as<u8>(16u - m_buf_len);
    for (usize i = m_buf_len; i < 16u; ++i) {
        m_buf[i] = pad;
    }
    // Update checksum with padded final block and compress it.
    u8 l = m_checksum[15];
    for (usize j = 0u; j < 16u; ++j) {
        const u8 c = m_buf[j];
        l = as<u8>(m_checksum[j] ^ kMd2Pi[as<usize>(c ^ l)]);
        m_checksum[j] = l;
    }
    transform(m_buf);
    // Compress the 16-byte checksum block (without updating checksum).
    transform(m_checksum);
    if (out) {
        copy_bytes(out, m_state, kDigestSize);
    }
    reset();
}

StaticArray<u8, Md2::kDigestSize> Md2::finalize() noexcept {
    StaticArray<u8, kDigestSize> out{};
    finalize(out.data());
    return out;
}

StaticArray<u8, Md2::kDigestSize> Md2::hash(ArrayRef<u8> data) noexcept {
    Md2 ctx;
    ctx.update(data);
    return ctx.finalize();
}

// ---------------------------------------------------------------------------
// MD5 (RFC 1321)
// ---------------------------------------------------------------------------

Md5::Md5() noexcept { reset(); }

Md5::~Md5() noexcept {
    secure_zero(m_state, sizeof(m_state));
    secure_zero(m_buf, sizeof(m_buf));
    m_total_bytes = 0u;
    m_buf_len = 0u;
}

void Md5::reset() noexcept {
    m_state[0] = 0x67452301u;
    m_state[1] = 0xEFCDAB89u;
    m_state[2] = 0x98BADCFEu;
    m_state[3] = 0x10325476u;
    m_total_bytes = 0u;
    m_buf_len = 0u;
    zero_bytes(m_buf, sizeof(m_buf));
}

void Md5::transform(const u8 block[64]) noexcept {
    u32 m[16];
    for (usize i = 0u; i < 16u; ++i) {
        m[i] = load_le32(block + i * 4u);
    }
    u32 a = m_state[0];
    u32 b = m_state[1];
    u32 c = m_state[2];
    u32 d = m_state[3];

    for (u32 i = 0u; i < 64u; ++i) {
        u32 f = 0u;
        u32 g = 0u;
        if (i < 16u) {
            f = (b & c) | ((~b) & d);
            g = i;
        } else if (i < 32u) {
            f = (d & b) | ((~d) & c);
            g = (5u * i + 1u) & 15u;
        } else if (i < 48u) {
            f = b ^ c ^ d;
            g = (3u * i + 5u) & 15u;
        } else {
            f = c ^ (b | (~d));
            g = (7u * i) & 15u;
        }
        const u32 tmp = d;
        d = c;
        c = b;
        b = b + rotl32(a + f + kMd5K[i] + m[g], kMd5Shift[i]);
        a = tmp;
    }

    m_state[0] += a;
    m_state[1] += b;
    m_state[2] += c;
    m_state[3] += d;
    secure_zero(m, sizeof(m));
}

void Md5::update(const u8* data, usize len) noexcept {
    if (!data || len == 0u) return;
    m_total_bytes += as<u64>(len);
    usize offset = 0u;
    if (m_buf_len > 0u) {
        const usize take = (len < 64u - m_buf_len) ? len : (64u - m_buf_len);
        copy_bytes(m_buf + m_buf_len, data, take);
        m_buf_len += take;
        offset += take;
        if (m_buf_len == 64u) {
            transform(m_buf);
            m_buf_len = 0u;
        }
    }
    while (offset + 64u <= len) {
        transform(data + offset);
        offset += 64u;
    }
    if (offset < len) {
        const usize rem = len - offset;
        copy_bytes(m_buf, data + offset, rem);
        m_buf_len = rem;
    }
}

void Md5::finalize(u8* out) noexcept {
    const u64 bit_len = m_total_bytes * 8u;
    m_buf[m_buf_len++] = 0x80u;
    if (m_buf_len > 56u) {
        zero_bytes(m_buf + m_buf_len, 64u - m_buf_len);
        transform(m_buf);
        m_buf_len = 0u;
    }
    zero_bytes(m_buf + m_buf_len, 56u - m_buf_len);
    store_le64(m_buf + 56u, bit_len);
    transform(m_buf);

    if (out) {
        for (usize i = 0u; i < 4u; ++i) {
            store_le32(out + i * 4u, m_state[i]);
        }
    }
    reset();
}

StaticArray<u8, Md5::kDigestSize> Md5::finalize() noexcept {
    StaticArray<u8, kDigestSize> out{};
    finalize(out.data());
    return out;
}

StaticArray<u8, Md5::kDigestSize> Md5::hash(ArrayRef<u8> data) noexcept {
    Md5 ctx;
    ctx.update(data);
    return ctx.finalize();
}

// ---------------------------------------------------------------------------
// SHA-1 (FIPS 180-4)
// ---------------------------------------------------------------------------

Sha1::Sha1() noexcept { reset(); }

Sha1::~Sha1() noexcept {
    secure_zero(m_state, sizeof(m_state));
    secure_zero(m_buf, sizeof(m_buf));
    m_total_bytes = 0u;
    m_buf_len = 0u;
}

void Sha1::reset() noexcept {
    m_state[0] = 0x67452301u;
    m_state[1] = 0xEFCDAB89u;
    m_state[2] = 0x98BADCFEu;
    m_state[3] = 0x10325476u;
    m_state[4] = 0xC3D2E1F0u;
    m_total_bytes = 0u;
    m_buf_len = 0u;
    zero_bytes(m_buf, sizeof(m_buf));
}

void Sha1::transform(const u8 block[64]) noexcept {
    u32 w[80];
    for (usize i = 0u; i < 16u; ++i) {
        w[i] = load_be32(block + i * 4u);
    }
    for (usize i = 16u; i < 80u; ++i) {
        w[i] = rotl32(w[i - 3u] ^ w[i - 8u] ^ w[i - 14u] ^ w[i - 16u], 1u);
    }

    u32 a = m_state[0];
    u32 b = m_state[1];
    u32 c = m_state[2];
    u32 d = m_state[3];
    u32 e = m_state[4];

    for (usize i = 0u; i < 80u; ++i) {
        u32 f = 0u;
        u32 k = 0u;
        if (i < 20u) {
            f = (b & c) | ((~b) & d);
            k = 0x5A827999u;
        } else if (i < 40u) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1u;
        } else if (i < 60u) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDCu;
        } else {
            f = b ^ c ^ d;
            k = 0xCA62C1D6u;
        }
        const u32 tmp = rotl32(a, 5u) + f + e + k + w[i];
        e = d;
        d = c;
        c = rotl32(b, 30u);
        b = a;
        a = tmp;
    }

    m_state[0] += a;
    m_state[1] += b;
    m_state[2] += c;
    m_state[3] += d;
    m_state[4] += e;
    secure_zero(w, sizeof(w));
}

void Sha1::update(const u8* data, usize len) noexcept {
    if (!data || len == 0u) return;
    m_total_bytes += as<u64>(len);
    usize offset = 0u;
    if (m_buf_len > 0u) {
        const usize take = (len < 64u - m_buf_len) ? len : (64u - m_buf_len);
        copy_bytes(m_buf + m_buf_len, data, take);
        m_buf_len += take;
        offset += take;
        if (m_buf_len == 64u) {
            transform(m_buf);
            m_buf_len = 0u;
        }
    }
    while (offset + 64u <= len) {
        transform(data + offset);
        offset += 64u;
    }
    if (offset < len) {
        const usize rem = len - offset;
        copy_bytes(m_buf, data + offset, rem);
        m_buf_len = rem;
    }
}

void Sha1::finalize(u8* out) noexcept {
    const u64 bit_len = m_total_bytes * 8u;
    m_buf[m_buf_len++] = 0x80u;
    if (m_buf_len > 56u) {
        zero_bytes(m_buf + m_buf_len, 64u - m_buf_len);
        transform(m_buf);
        m_buf_len = 0u;
    }
    zero_bytes(m_buf + m_buf_len, 56u - m_buf_len);
    store_be64(m_buf + 56u, bit_len);
    transform(m_buf);

    if (out) {
        for (usize i = 0u; i < 5u; ++i) {
            store_be32(out + i * 4u, m_state[i]);
        }
    }
    reset();
}

StaticArray<u8, Sha1::kDigestSize> Sha1::finalize() noexcept {
    StaticArray<u8, kDigestSize> out{};
    finalize(out.data());
    return out;
}

StaticArray<u8, Sha1::kDigestSize> Sha1::hash(ArrayRef<u8> data) noexcept {
    Sha1 ctx;
    ctx.update(data);
    return ctx.finalize();
}

// ---------------------------------------------------------------------------
// SHA-256 & SHA-224 (FIPS 180-4)
// ---------------------------------------------------------------------------

Sha256::Sha256() noexcept { reset(); }

Sha256::~Sha256() noexcept {
    secure_zero(m_state, sizeof(m_state));
    secure_zero(m_buf, sizeof(m_buf));
    m_total_bytes = 0u;
    m_buf_len = 0u;
}

void Sha256::reset_with_iv(const u32 iv[8]) noexcept {
    for (usize i = 0u; i < 8u; ++i) {
        m_state[i] = iv[i];
    }
    m_total_bytes = 0u;
    m_buf_len = 0u;
    zero_bytes(m_buf, sizeof(m_buf));
}

void Sha256::reset() noexcept { reset_with_iv(kSha256Iv); }

void Sha256::transform(const u8 block[64]) noexcept {
    u32 w[64];
    for (usize i = 0u; i < 16u; ++i) {
        w[i] = load_be32(block + i * 4u);
    }
    for (usize i = 16u; i < 64u; ++i) {
        const u32 s0 = rotr32(w[i - 15u], 7u) ^ rotr32(w[i - 15u], 18u) ^ (w[i - 15u] >> 3u);
        const u32 s1 = rotr32(w[i - 2u], 17u) ^ rotr32(w[i - 2u], 19u) ^ (w[i - 2u] >> 10u);
        w[i] = w[i - 16u] + s0 + w[i - 7u] + s1;
    }

    u32 a = m_state[0];
    u32 b = m_state[1];
    u32 c = m_state[2];
    u32 d = m_state[3];
    u32 e = m_state[4];
    u32 f = m_state[5];
    u32 g = m_state[6];
    u32 h = m_state[7];

    for (usize i = 0u; i < 64u; ++i) {
        const u32 s1 = rotr32(e, 6u) ^ rotr32(e, 11u) ^ rotr32(e, 25u);
        const u32 ch = (e & f) ^ ((~e) & g);
        const u32 t1 = h + s1 + ch + kSha256K[i] + w[i];
        const u32 s0 = rotr32(a, 2u) ^ rotr32(a, 13u) ^ rotr32(a, 22u);
        const u32 maj = (a & b) ^ (a & c) ^ (b & c);
        const u32 t2 = s0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    m_state[0] += a;
    m_state[1] += b;
    m_state[2] += c;
    m_state[3] += d;
    m_state[4] += e;
    m_state[5] += f;
    m_state[6] += g;
    m_state[7] += h;
    secure_zero(w, sizeof(w));
}

void Sha256::update(const u8* data, usize len) noexcept {
    if (!data || len == 0u) return;
    m_total_bytes += as<u64>(len);
    usize offset = 0u;
    if (m_buf_len > 0u) {
        const usize take = (len < 64u - m_buf_len) ? len : (64u - m_buf_len);
        copy_bytes(m_buf + m_buf_len, data, take);
        m_buf_len += take;
        offset += take;
        if (m_buf_len == 64u) {
            transform(m_buf);
            m_buf_len = 0u;
        }
    }
    while (offset + 64u <= len) {
        transform(data + offset);
        offset += 64u;
    }
    if (offset < len) {
        const usize rem = len - offset;
        copy_bytes(m_buf, data + offset, rem);
        m_buf_len = rem;
    }
}

void Sha256::finalize_truncated(u8* out, usize out_bytes) noexcept {
    const u64 bit_len = m_total_bytes * 8u;
    m_buf[m_buf_len++] = 0x80u;
    if (m_buf_len > 56u) {
        zero_bytes(m_buf + m_buf_len, 64u - m_buf_len);
        transform(m_buf);
        m_buf_len = 0u;
    }
    zero_bytes(m_buf + m_buf_len, 56u - m_buf_len);
    store_be64(m_buf + 56u, bit_len);
    transform(m_buf);

    if (out) {
        const usize words = out_bytes / 4u;
        for (usize i = 0u; i < words; ++i) {
            store_be32(out + i * 4u, m_state[i]);
        }
    }
}

void Sha256::finalize(u8* out) noexcept {
    finalize_truncated(out, kDigestSize);
    reset();
}

StaticArray<u8, Sha256::kDigestSize> Sha256::finalize() noexcept {
    StaticArray<u8, kDigestSize> out{};
    finalize(out.data());
    return out;
}

StaticArray<u8, Sha256::kDigestSize> Sha256::hash(ArrayRef<u8> data) noexcept {
    Sha256 ctx;
    ctx.update(data);
    return ctx.finalize();
}

Sha224::Sha224() noexcept { reset(); }
Sha224::~Sha224() noexcept = default;
void Sha224::reset() noexcept { m_core.reset_with_iv(kSha224Iv); }
void Sha224::update(const u8* data, usize len) noexcept { m_core.update(data, len); }

void Sha224::finalize(u8* out) noexcept {
    m_core.finalize_truncated(out, kDigestSize);
    reset();
}

StaticArray<u8, Sha224::kDigestSize> Sha224::finalize() noexcept {
    StaticArray<u8, kDigestSize> out{};
    finalize(out.data());
    return out;
}

StaticArray<u8, Sha224::kDigestSize> Sha224::hash(ArrayRef<u8> data) noexcept {
    Sha224 ctx;
    ctx.update(data);
    return ctx.finalize();
}

// ---------------------------------------------------------------------------
// SHA-512 & SHA-384 (FIPS 180-4)
// ---------------------------------------------------------------------------

Sha512::Sha512() noexcept { reset(); }

Sha512::~Sha512() noexcept {
    secure_zero(m_state, sizeof(m_state));
    secure_zero(m_buf, sizeof(m_buf));
    m_total_lo = 0u;
    m_total_hi = 0u;
    m_buf_len = 0u;
}

void Sha512::reset_with_iv(const u64 iv[8]) noexcept {
    for (usize i = 0u; i < 8u; ++i) {
        m_state[i] = iv[i];
    }
    m_total_lo = 0u;
    m_total_hi = 0u;
    m_buf_len = 0u;
    zero_bytes(m_buf, sizeof(m_buf));
}

void Sha512::reset() noexcept { reset_with_iv(kSha512Iv); }

void Sha512::transform(const u8 block[128]) noexcept {
    u64 w[80];
    for (usize i = 0u; i < 16u; ++i) {
        w[i] = load_be64(block + i * 8u);
    }
    for (usize i = 16u; i < 80u; ++i) {
        const u64 s0 = rotr64(w[i - 15u], 1u) ^ rotr64(w[i - 15u], 8u) ^ (w[i - 15u] >> 7u);
        const u64 s1 = rotr64(w[i - 2u], 19u) ^ rotr64(w[i - 2u], 61u) ^ (w[i - 2u] >> 6u);
        w[i] = w[i - 16u] + s0 + w[i - 7u] + s1;
    }

    u64 a = m_state[0];
    u64 b = m_state[1];
    u64 c = m_state[2];
    u64 d = m_state[3];
    u64 e = m_state[4];
    u64 f = m_state[5];
    u64 g = m_state[6];
    u64 h = m_state[7];

    for (usize i = 0u; i < 80u; ++i) {
        const u64 s1 = rotr64(e, 14u) ^ rotr64(e, 18u) ^ rotr64(e, 41u);
        const u64 ch = (e & f) ^ ((~e) & g);
        const u64 t1 = h + s1 + ch + kSha512K[i] + w[i];
        const u64 s0 = rotr64(a, 28u) ^ rotr64(a, 34u) ^ rotr64(a, 39u);
        const u64 maj = (a & b) ^ (a & c) ^ (b & c);
        const u64 t2 = s0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    m_state[0] += a;
    m_state[1] += b;
    m_state[2] += c;
    m_state[3] += d;
    m_state[4] += e;
    m_state[5] += f;
    m_state[6] += g;
    m_state[7] += h;
    secure_zero(w, sizeof(w));
}

void Sha512::update(const u8* data, usize len) noexcept {
    if (!data || len == 0u) return;
    const u64 add = as<u64>(len);
    const u64 prev = m_total_lo;
    m_total_lo += add;
    if (m_total_lo < prev) {
        ++m_total_hi;
    }

    usize offset = 0u;
    if (m_buf_len > 0u) {
        const usize take = (len < 128u - m_buf_len) ? len : (128u - m_buf_len);
        copy_bytes(m_buf + m_buf_len, data, take);
        m_buf_len += take;
        offset += take;
        if (m_buf_len == 128u) {
            transform(m_buf);
            m_buf_len = 0u;
        }
    }
    while (offset + 128u <= len) {
        transform(data + offset);
        offset += 128u;
    }
    if (offset < len) {
        const usize rem = len - offset;
        copy_bytes(m_buf, data + offset, rem);
        m_buf_len = rem;
    }
}

void Sha512::finalize_truncated(u8* out, usize out_bytes) noexcept {
    const u64 bits_hi = (m_total_hi << 3u) | (m_total_lo >> 61u);
    const u64 bits_lo = m_total_lo << 3u;

    m_buf[m_buf_len++] = 0x80u;
    if (m_buf_len > 112u) {
        zero_bytes(m_buf + m_buf_len, 128u - m_buf_len);
        transform(m_buf);
        m_buf_len = 0u;
    }
    zero_bytes(m_buf + m_buf_len, 112u - m_buf_len);
    store_be64(m_buf + 112u, bits_hi);
    store_be64(m_buf + 120u, bits_lo);
    transform(m_buf);

    if (out) {
        const usize words = out_bytes / 8u;
        for (usize i = 0u; i < words; ++i) {
            store_be64(out + i * 8u, m_state[i]);
        }
    }
}

void Sha512::finalize(u8* out) noexcept {
    finalize_truncated(out, kDigestSize);
    reset();
}

StaticArray<u8, Sha512::kDigestSize> Sha512::finalize() noexcept {
    StaticArray<u8, kDigestSize> out{};
    finalize(out.data());
    return out;
}

StaticArray<u8, Sha512::kDigestSize> Sha512::hash(ArrayRef<u8> data) noexcept {
    Sha512 ctx;
    ctx.update(data);
    return ctx.finalize();
}

Sha384::Sha384() noexcept { reset(); }
Sha384::~Sha384() noexcept = default;
void Sha384::reset() noexcept { m_core.reset_with_iv(kSha384Iv); }
void Sha384::update(const u8* data, usize len) noexcept { m_core.update(data, len); }

void Sha384::finalize(u8* out) noexcept {
    m_core.finalize_truncated(out, kDigestSize);
    reset();
}

StaticArray<u8, Sha384::kDigestSize> Sha384::finalize() noexcept {
    StaticArray<u8, kDigestSize> out{};
    finalize(out.data());
    return out;
}

StaticArray<u8, Sha384::kDigestSize> Sha384::hash(ArrayRef<u8> data) noexcept {
    Sha384 ctx;
    ctx.update(data);
    return ctx.finalize();
}

// ---------------------------------------------------------------------------
// Stack-allocated polymorphic Digest
// ---------------------------------------------------------------------------

void Digest::construct_active() noexcept {
    switch (m_alg) {
        case DigestAlgorithm::Md2: ::new (&m_storage.md2) Md2(); break;
        case DigestAlgorithm::Md5: ::new (&m_storage.md5) Md5(); break;
        case DigestAlgorithm::Sha1: ::new (&m_storage.sha1) Sha1(); break;
        case DigestAlgorithm::Sha224: ::new (&m_storage.sha224) Sha224(); break;
        case DigestAlgorithm::Sha256: ::new (&m_storage.sha256) Sha256(); break;
        case DigestAlgorithm::Sha384: ::new (&m_storage.sha384) Sha384(); break;
        case DigestAlgorithm::Sha512: ::new (&m_storage.sha512) Sha512(); break;
    }
}

void Digest::copy_active_from(const Digest& other) noexcept {
    switch (m_alg) {
        case DigestAlgorithm::Md2: ::new (&m_storage.md2) Md2(other.m_storage.md2); break;
        case DigestAlgorithm::Md5: ::new (&m_storage.md5) Md5(other.m_storage.md5); break;
        case DigestAlgorithm::Sha1: ::new (&m_storage.sha1) Sha1(other.m_storage.sha1); break;
        case DigestAlgorithm::Sha224: ::new (&m_storage.sha224) Sha224(other.m_storage.sha224); break;
        case DigestAlgorithm::Sha256: ::new (&m_storage.sha256) Sha256(other.m_storage.sha256); break;
        case DigestAlgorithm::Sha384: ::new (&m_storage.sha384) Sha384(other.m_storage.sha384); break;
        case DigestAlgorithm::Sha512: ::new (&m_storage.sha512) Sha512(other.m_storage.sha512); break;
    }
}

void Digest::destroy_active() noexcept {
    switch (m_alg) {
        case DigestAlgorithm::Md2: m_storage.md2.~Md2(); break;
        case DigestAlgorithm::Md5: m_storage.md5.~Md5(); break;
        case DigestAlgorithm::Sha1: m_storage.sha1.~Sha1(); break;
        case DigestAlgorithm::Sha224: m_storage.sha224.~Sha224(); break;
        case DigestAlgorithm::Sha256: m_storage.sha256.~Sha256(); break;
        case DigestAlgorithm::Sha384: m_storage.sha384.~Sha384(); break;
        case DigestAlgorithm::Sha512: m_storage.sha512.~Sha512(); break;
    }
}

Digest::Digest(DigestAlgorithm alg) noexcept : m_alg(alg) { construct_active(); }

Digest::~Digest() noexcept { destroy_active(); }

Digest::Digest(const Digest& other) noexcept : m_alg(other.m_alg) { copy_active_from(other); }

Digest& Digest::operator=(const Digest& other) noexcept {
    if (this != &other) {
        destroy_active();
        m_alg = other.m_alg;
        copy_active_from(other);
    }
    return *this;
}

Optional<Digest> Digest::create(StringRef alg_name) noexcept {
    const auto alg = parse_digest_algorithm(alg_name);
    if (!alg.has_value()) return {};
    return Digest(*alg);
}

void Digest::reset() noexcept {
    switch (m_alg) {
        case DigestAlgorithm::Md2: m_storage.md2.reset(); break;
        case DigestAlgorithm::Md5: m_storage.md5.reset(); break;
        case DigestAlgorithm::Sha1: m_storage.sha1.reset(); break;
        case DigestAlgorithm::Sha224: m_storage.sha224.reset(); break;
        case DigestAlgorithm::Sha256: m_storage.sha256.reset(); break;
        case DigestAlgorithm::Sha384: m_storage.sha384.reset(); break;
        case DigestAlgorithm::Sha512: m_storage.sha512.reset(); break;
    }
}

void Digest::update(const u8* data, usize len) noexcept {
    switch (m_alg) {
        case DigestAlgorithm::Md2: m_storage.md2.update(data, len); break;
        case DigestAlgorithm::Md5: m_storage.md5.update(data, len); break;
        case DigestAlgorithm::Sha1: m_storage.sha1.update(data, len); break;
        case DigestAlgorithm::Sha224: m_storage.sha224.update(data, len); break;
        case DigestAlgorithm::Sha256: m_storage.sha256.update(data, len); break;
        case DigestAlgorithm::Sha384: m_storage.sha384.update(data, len); break;
        case DigestAlgorithm::Sha512: m_storage.sha512.update(data, len); break;
    }
}

usize Digest::finalize(MutArrayRef<u8> out) noexcept {
    const usize sz = output_size();
    if (out.size() < sz) return 0u;
    switch (m_alg) {
        case DigestAlgorithm::Md2: m_storage.md2.finalize(out.data()); break;
        case DigestAlgorithm::Md5: m_storage.md5.finalize(out.data()); break;
        case DigestAlgorithm::Sha1: m_storage.sha1.finalize(out.data()); break;
        case DigestAlgorithm::Sha224: m_storage.sha224.finalize(out.data()); break;
        case DigestAlgorithm::Sha256: m_storage.sha256.finalize(out.data()); break;
        case DigestAlgorithm::Sha384: m_storage.sha384.finalize(out.data()); break;
        case DigestAlgorithm::Sha512: m_storage.sha512.finalize(out.data()); break;
    }
    return sz;
}

Array<u8> Digest::finalize(Allocator* alloc) {
    Array<u8> out(alloc);
    out.resize(output_size());
    (void)finalize(out.as_mut_ref());
    return out;
}

Array<u8> Digest::hash(DigestAlgorithm alg, ArrayRef<u8> data, Allocator* alloc) {
    Digest d(alg);
    d.update(data);
    return d.finalize(alloc);
}

} // namespace keel::crypto
