#include "keel/crypto.h"
#include "keel/format.h"
#include "keel/io.h"

namespace {

using namespace keel;
using namespace keel::crypto;

i32 g_failures = 0;

void check_eq_str(StringRef label, StringRef got, StringRef expected) {
    if (got != expected) {
        const String msg = format("FAIL {}: got={} expected={}\n", label, got, expected);
        stderr_write(msg.as_ref());
        ++g_failures;
    }
}

void check_true(StringRef label, bool cond) {
    if (!cond) {
        const String msg = format("FAIL {}\n", label);
        stderr_write(msg.as_ref());
        ++g_failures;
    }
}

Array<u8> hex_bytes(StringRef hex) {
    auto res = from_hex(hex);
    check_true("from_hex valid", res.has_value());
    return res.has_value() ? keel::move(*res) : Array<u8>();
}

void test_ct_and_hex() {
    u8 a[4] = {0xDEu, 0xADu, 0xBEu, 0xEFu};
    u8 b[4] = {0xDEu, 0xADu, 0xBEu, 0xEFu};
    u8 c[4] = {0xDEu, 0xADu, 0xBEu, 0xEEu};

    check_true("ct_equal same", ct_equal(ArrayRef<u8>(a, 4u), ArrayRef<u8>(b, 4u)));
    check_true("ct_equal diff", !ct_equal(ArrayRef<u8>(a, 4u), ArrayRef<u8>(c, 4u)));
    check_true("ct_equal len", !ct_equal(ArrayRef<u8>(a, 4u), ArrayRef<u8>(b, 3u)));

    check_eq_str("to_hex lower", to_hex(ArrayRef<u8>(a, 4u)).as_ref(), "deadbeef");
    check_eq_str("to_hex upper", to_hex(ArrayRef<u8>(a, 4u), true).as_ref(), "DEADBEEF");

    auto parsed = from_hex("DeAdBeEf");
    check_true("from_hex ok", parsed.has_value() && ct_equal(parsed->as_ref(), ArrayRef<u8>(a, 4u)));
    check_true("from_hex odd", !from_hex("abc").has_value());
    check_true("from_hex bad", !from_hex("zz").has_value());

    secure_zero(a, 4u);
    check_true("secure_zero", a[0] == 0u && a[1] == 0u && a[2] == 0u && a[3] == 0u);
}

void test_md2_rfc1319() {
    check_eq_str("MD2 empty", to_hex(md2(StringRef("")).as_ref()).as_ref(),
                 "8350e5a3e24c153df2275c9f80692773");
    check_eq_str("MD2 a", to_hex(md2(StringRef("a")).as_ref()).as_ref(),
                 "32ec01ec4a6dac72c0ab96fb34c0b5d1");
    check_eq_str("MD2 abc", to_hex(md2(StringRef("abc")).as_ref()).as_ref(),
                 "da853b0d3f88d99b30283a69e6ded6bb");
    check_eq_str("MD2 message digest", to_hex(md2(StringRef("message digest")).as_ref()).as_ref(),
                 "ab4f496bfb2a530b219ff33031fe06b0");
    check_eq_str("MD2 a-z", to_hex(md2(StringRef("abcdefghijklmnopqrstuvwxyz")).as_ref()).as_ref(),
                 "4e8ddff3650292ab5a4108c3aa47940b");
    check_eq_str("MD2 alnum",
                 to_hex(md2(StringRef("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")).as_ref()).as_ref(),
                 "da33def2a42df13975352846c30338cd");
    check_eq_str("MD2 digits80",
                 to_hex(md2(StringRef("12345678901234567890123456789012345678901234567890123456789012345678901234567890")).as_ref()).as_ref(),
                 "d5976f79d83d3a0dc9806c3c66f3efd8");
}

void test_md5_rfc1321() {
    check_eq_str("MD5 empty", to_hex(md5(StringRef("")).as_ref()).as_ref(),
                 "d41d8cd98f00b204e9800998ecf8427e");
    check_eq_str("MD5 a", to_hex(md5(StringRef("a")).as_ref()).as_ref(),
                 "0cc175b9c0f1b6a831c399e269772661");
    check_eq_str("MD5 abc", to_hex(md5(StringRef("abc")).as_ref()).as_ref(),
                 "900150983cd24fb0d6963f7d28e17f72");
    check_eq_str("MD5 message digest", to_hex(md5(StringRef("message digest")).as_ref()).as_ref(),
                 "f96b697d7cb7938d525a2f31aaf161d0");
    check_eq_str("MD5 a-z", to_hex(md5(StringRef("abcdefghijklmnopqrstuvwxyz")).as_ref()).as_ref(),
                 "c3fcd3d76192e4007dfb496cca67e13b");
    check_eq_str("MD5 alnum",
                 to_hex(md5(StringRef("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")).as_ref()).as_ref(),
                 "d174ab98d277d9f5a5611c2c9f419d9f");
    check_eq_str("MD5 digits80",
                 to_hex(md5(StringRef("12345678901234567890123456789012345678901234567890123456789012345678901234567890")).as_ref()).as_ref(),
                 "57edf4a22be3c955ac49da2e2107b67a");
}

void test_sha1_fips() {
    check_eq_str("SHA1 empty", to_hex(sha1(StringRef("")).as_ref()).as_ref(),
                 "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    check_eq_str("SHA1 abc", to_hex(sha1(StringRef("abc")).as_ref()).as_ref(),
                 "a9993e364706816aba3e25717850c26c9cd0d89d");
    check_eq_str("SHA1 448bit",
                 to_hex(sha1(StringRef("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")).as_ref()).as_ref(),
                 "84983e441c3bd26ebaae4aa1f95129e5e54670f1");
    // 1,000,000 'a' bytes
    Sha1 million;
    u8 chunk[1000];
    for (usize i = 0u; i < 1000u; ++i) chunk[i] = as<u8>('a');
    for (usize i = 0u; i < 1000u; ++i) million.update(chunk, 1000u);
    check_eq_str("SHA1 1M a", to_hex(million.finalize().as_ref()).as_ref(),
                 "34aa973cd4c4daa4f61eeb2bdbad27316534016f");
}

void test_sha2_fips() {
    // SHA-224
    check_eq_str("SHA224 empty", to_hex(sha224(StringRef("")).as_ref()).as_ref(),
                 "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f");
    check_eq_str("SHA224 abc", to_hex(sha224(StringRef("abc")).as_ref()).as_ref(),
                 "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7");
    check_eq_str("SHA224 448bit",
                 to_hex(sha224(StringRef("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")).as_ref()).as_ref(),
                 "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525");

    // SHA-256
    check_eq_str("SHA256 empty", to_hex(sha256(StringRef("")).as_ref()).as_ref(),
                 "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    check_eq_str("SHA256 abc", to_hex(sha256(StringRef("abc")).as_ref()).as_ref(),
                 "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    check_eq_str("SHA256 448bit",
                 to_hex(sha256(StringRef("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")).as_ref()).as_ref(),
                 "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    Sha256 m256;
    u8 chunk[1000];
    for (usize i = 0u; i < 1000u; ++i) chunk[i] = as<u8>('a');
    for (usize i = 0u; i < 1000u; ++i) m256.update(chunk, 1000u);
    check_eq_str("SHA256 1M a", to_hex(m256.finalize().as_ref()).as_ref(),
                 "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");

    // SHA-384
    check_eq_str("SHA384 empty", to_hex(sha384(StringRef("")).as_ref()).as_ref(),
                 "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");
    check_eq_str("SHA384 abc", to_hex(sha384(StringRef("abc")).as_ref()).as_ref(),
                 "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7");
    check_eq_str("SHA384 896bit",
                 to_hex(sha384(StringRef("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu")).as_ref()).as_ref(),
                 "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039");

    // SHA-512
    check_eq_str("SHA512 empty", to_hex(sha512(StringRef("")).as_ref()).as_ref(),
                 "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
    check_eq_str("SHA512 abc", to_hex(sha512(StringRef("abc")).as_ref()).as_ref(),
                 "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
    check_eq_str("SHA512 896bit",
                 to_hex(sha512(StringRef("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu")).as_ref()).as_ref(),
                 "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909");
}

void test_polymorphic_digest_and_streaming() {
    auto d = Digest::create("sha256");
    check_true("create sha256", d.has_value() && d->algorithm() == DigestAlgorithm::Sha256);
    check_eq_str("alg name", d->algorithm_name(), "SHA-256");
    check_true("bad alg", !Digest::create("UNKNOWN-999").has_value());

    // Stream byte-by-byte vs one-shot and verify auto-reset after finalize
    const StringRef msg = "The quick brown fox jumps over the lazy dog";
    for (usize i = 0u; i < msg.size(); ++i) {
        d->update(reinterpret_cast<const u8*>(msg.data() + i), 1u);
    }
    const Array<u8> h1 = d->finalize();
    check_eq_str("streaming sha256", to_hex(h1.as_ref()).as_ref(),
                 "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592");

    // Second finalize immediately after reset must match empty hash
    const Array<u8> h_empty = d->finalize();
    check_eq_str("auto-reset sha256", to_hex(h_empty.as_ref()).as_ref(),
                 "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    // Copy mid-stream
    Digest d2(DigestAlgorithm::Sha512);
    d2.update(StringRef("abc"));
    Digest d3 = d2;
    d3.update(StringRef("def"));
    check_eq_str("copy original", to_hex(d2.finalize().as_ref()).as_ref(),
                 to_hex(sha512(StringRef("abc")).as_ref()).as_ref());
    check_eq_str("copy fork", to_hex(d3.finalize().as_ref()).as_ref(),
                 to_hex(sha512(StringRef("abcdef")).as_ref()).as_ref());
}

void test_hmac_rfc4231() {
    // Test Case 1: key = 20x 0x0b, data = "Hi There"
    const Array<u8> k1 = hex_bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    const StringRef d1 = "Hi There";
    const ArrayRef<u8> d1_bytes(reinterpret_cast<const u8*>(d1.data()), d1.size());
    check_eq_str("HMAC-SHA256 TC1",
                 to_hex(Hmac::compute(DigestAlgorithm::Sha256, k1.as_ref(), d1_bytes).as_ref()).as_ref(),
                 "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    check_eq_str("HMAC-SHA384 TC1",
                 to_hex(Hmac::compute(DigestAlgorithm::Sha384, k1.as_ref(), d1_bytes).as_ref()).as_ref(),
                 "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6");
    check_eq_str("HMAC-SHA512 TC1",
                 to_hex(Hmac::compute(DigestAlgorithm::Sha512, k1.as_ref(), d1_bytes).as_ref()).as_ref(),
                 "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854");

    // Test Case 6: key longer than block size (131 bytes of 0xaa)
    Array<u8> k6;
    k6.resize(131u);
    for (usize i = 0u; i < 131u; ++i) k6[i] = 0xAAu;
    const StringRef d6 = "Test Using Larger Than Block-Size Key - Hash Key First";
    const ArrayRef<u8> d6_bytes(reinterpret_cast<const u8*>(d6.data()), d6.size());
    check_eq_str("HMAC-SHA256 TC6",
                 to_hex(Hmac::compute(DigestAlgorithm::Sha256, k6.as_ref(), d6_bytes).as_ref()).as_ref(),
                 "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
    check_eq_str("HMAC-SHA512 TC6",
                 to_hex(Hmac::compute(DigestAlgorithm::Sha512, k6.as_ref(), d6_bytes).as_ref()).as_ref(),
                 "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598");

    const Array<u8> expected_tag = hex_bytes("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
    check_true("HMAC verify ok", Hmac::verify(DigestAlgorithm::Sha256, k6.as_ref(), d6_bytes, expected_tag.as_ref()));
    Array<u8> bad_tag = expected_tag.clone();
    bad_tag[0] ^= 1u;
    check_true("HMAC verify bad", !Hmac::verify(DigestAlgorithm::Sha256, k6.as_ref(), d6_bytes, bad_tag.as_ref()));
}

void test_kdf_rfcs() {
    // RFC 5869 HKDF-SHA256 Test Case 1
    const Array<u8> ikm1 = hex_bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    const Array<u8> salt1 = hex_bytes("000102030405060708090a0b0c");
    const Array<u8> info1 = hex_bytes("f0f1f2f3f4f5f6f7f8f9");
    const auto okm1 = hkdf(DigestAlgorithm::Sha256, salt1.as_ref(), ikm1.as_ref(), info1.as_ref(), 42u);
    check_true("HKDF TC1 has value", okm1.has_value());
    if (okm1.has_value()) {
        check_eq_str("HKDF TC1", to_hex(okm1->as_ref()).as_ref(),
                     "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
    }

    // RFC 5869 HKDF-SHA256 Test Case 3 (empty salt & info)
    const auto okm3 = hkdf(DigestAlgorithm::Sha256, ArrayRef<u8>(), ikm1.as_ref(), ArrayRef<u8>(), 42u);
    check_true("HKDF TC3 has value", okm3.has_value());
    if (okm3.has_value()) {
        check_eq_str("HKDF TC3", to_hex(okm3->as_ref()).as_ref(),
                     "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8");
    }

    // RFC 6070 PBKDF2-HMAC-SHA1 Test Case 1 & 2
    const StringRef pw = "password";
    const StringRef st = "salt";
    const ArrayRef<u8> pw_b(reinterpret_cast<const u8*>(pw.data()), pw.size());
    const ArrayRef<u8> st_b(reinterpret_cast<const u8*>(st.data()), st.size());

    const auto dk1 = pbkdf2_hmac(DigestAlgorithm::Sha1, pw_b, st_b, 1u, 20u);
    check_true("PBKDF2 TC1", dk1.has_value());
    if (dk1.has_value()) {
        check_eq_str("PBKDF2 TC1 hex", to_hex(dk1->as_ref()).as_ref(),
                     "0c60c80f961f0e71f3a9b524af6012062fe037a6");
    }
    const auto dk2 = pbkdf2_hmac(DigestAlgorithm::Sha1, pw_b, st_b, 2u, 20u);
    check_true("PBKDF2 TC2", dk2.has_value());
    if (dk2.has_value()) {
        check_eq_str("PBKDF2 TC2 hex", to_hex(dk2->as_ref()).as_ref(),
                     "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957");
    }
    const auto dk3 = pbkdf2_hmac(DigestAlgorithm::Sha1, pw_b, st_b, 4096u, 20u);
    check_true("PBKDF2 TC3", dk3.has_value());
    if (dk3.has_value()) {
        check_eq_str("PBKDF2 TC3 hex", to_hex(dk3->as_ref()).as_ref(),
                     "4b007901b765489abead49d926f721d065a429c1");
    }
    check_true("PBKDF2 iter=0 rejected", !pbkdf2_hmac(DigestAlgorithm::Sha1, pw_b, st_b, 0u, 20u).has_value());
}

} // namespace

int main(int argc, char** argv) {
    // Optional CLI mode for cross-verification scripts:
    //   test_crypto --hash <alg> <hex_msg>
    //   test_crypto --hmac <alg> <hex_key> <hex_msg>
    if (argc == 4 && StringRef(argv[1]) == "--hash") {
        auto d = Digest::create(StringRef(argv[2]));
        auto msg = from_hex(StringRef(argv[3]));
        if (!d.has_value() || !msg.has_value()) return 2;
        d->update(msg->as_ref());
        const String line = format("{}\n", to_hex(d->finalize().as_ref()));
        stdout_write(line.as_ref());
        return 0;
    }
    if (argc == 5 && StringRef(argv[1]) == "--hmac") {
        auto alg = parse_digest_algorithm(StringRef(argv[2]));
        auto key = from_hex(StringRef(argv[3]));
        auto msg = from_hex(StringRef(argv[4]));
        if (!alg.has_value() || !key.has_value() || !msg.has_value()) return 2;
        const String line = format("{}\n", to_hex(Hmac::compute(*alg, key->as_ref(), msg->as_ref()).as_ref()));
        stdout_write(line.as_ref());
        return 0;
    }

    test_ct_and_hex();
    test_md2_rfc1319();
    test_md5_rfc1321();
    test_sha1_fips();
    test_sha2_fips();
    test_polymorphic_digest_and_streaming();
    test_hmac_rfc4231();
    test_kdf_rfcs();

    if (g_failures == 0) {
        stdout_write("ALL keel_crypto tests PASSED.\n");
        return 0;
    }
    const String summary = format("keel_crypto tests FAILED: {} failure(s).\n", g_failures);
    stderr_write(summary.as_ref());
    return 1;
}
