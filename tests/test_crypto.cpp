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

void test_aes_fips197_and_modes() {
    // FIPS-197 Appendix C.1 (AES-128), C.2 (AES-192), C.3 (AES-256)
    const Array<u8> pt = hex_bytes("00112233445566778899aabbccddeeff");

    {
        const Array<u8> k128 = hex_bytes("000102030405060708090a0b0c0d0e0f");
        Aes aes;
        check_true("AES-128 init", aes.init(k128.as_ref()) && aes.rounds() == 10u);
        u8 ct[16] = {};
        u8 dec[16] = {};
        aes.encrypt_block(pt.data(), ct);
        check_eq_str("FIPS-197 AES-128 enc", to_hex(ArrayRef<u8>(ct, 16u)).as_ref(),
                     "69c4e0d86a7b0430d8cdb78070b4c55a");
        aes.decrypt_block(ct, dec);
        check_eq_str("FIPS-197 AES-128 dec", to_hex(ArrayRef<u8>(dec, 16u)).as_ref(),
                     "00112233445566778899aabbccddeeff");
    }
    {
        const Array<u8> k192 = hex_bytes("000102030405060708090a0b0c0d0e0f1011121314151617");
        Aes aes;
        check_true("AES-192 init", aes.init(k192.as_ref()) && aes.rounds() == 12u);
        u8 ct[16] = {};
        u8 dec[16] = {};
        aes.encrypt_block(pt.data(), ct);
        check_eq_str("FIPS-197 AES-192 enc", to_hex(ArrayRef<u8>(ct, 16u)).as_ref(),
                     "dda97ca4864cdfe06eaf70a0ec0d7191");
        aes.decrypt_block(ct, dec);
        check_eq_str("FIPS-197 AES-192 dec", to_hex(ArrayRef<u8>(dec, 16u)).as_ref(),
                     "00112233445566778899aabbccddeeff");
    }
    {
        const Array<u8> k256 = hex_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        Aes aes;
        check_true("AES-256 init", aes.init(k256.as_ref()) && aes.rounds() == 14u);
        u8 ct[16] = {};
        u8 dec[16] = {};
        aes.encrypt_block(pt.data(), ct);
        check_eq_str("FIPS-197 AES-256 enc", to_hex(ArrayRef<u8>(ct, 16u)).as_ref(),
                     "8ea2b7ca516745bfeafc49904b496089");
        aes.decrypt_block(ct, dec);
        check_eq_str("FIPS-197 AES-256 dec", to_hex(ArrayRef<u8>(dec, 16u)).as_ref(),
                     "00112233445566778899aabbccddeeff");
    }

    // Invalid key length rejected
    {
        const Array<u8> badk = hex_bytes("0001020304050607");
        Aes aes;
        check_true("AES bad key len", !aes.init(badk.as_ref()) && !aes.valid());
    }

    // NIST SP 800-38A F.2.1 CBC-AES128.Encrypt & F.5.1 CTR-AES128.Encrypt
    {
        const Array<u8> key = hex_bytes("2b7e151628aed2a6abf7158809cf4f3c");
        const Array<u8> iv = hex_bytes("000102030405060708090a0b0c0d0e0f");
        const Array<u8> msg = hex_bytes(
            "6bc1bee22e409f96e93d7e117393172a"
            "ae2d8a571e03ac9c9eb76fac45af8e51"
            "30c81c46a35ce411e5fbc1191a0a52ef"
            "f69f2445df4f9b17ad2b417be66c3710");
        const StringRef expected_cbc =
            "7649abac8119b246cee98e9b12e9197d"
            "5086cb9b507219ee95db113a917678b2"
            "73bed6b8e3c1743b7116e69e22229516"
            "3ff1caa1681fac09120eca307586e1a7";

        Array<u8> ct(msg.size(), u8{0u});
        Array<u8> dec(msg.size(), u8{0u});
        check_true("CBC-128 raw enc ok", aes_cbc_encrypt_blocks(key.as_ref(), iv.data(), msg.as_ref(), ct.as_mut_ref()));
        check_eq_str("NIST CBC-128 enc", to_hex(ct.as_ref()).as_ref(), expected_cbc);
        check_true("CBC-128 raw dec ok", aes_cbc_decrypt_blocks(key.as_ref(), iv.data(), ct.as_ref(), dec.as_mut_ref()));
        check_true("NIST CBC-128 dec", ct_equal(dec.as_ref(), msg.as_ref()));

        // PKCS#7 round-trip: empty, partial, exact block
        const usize lengths[4] = {0u, 1u, 15u, 16u};
        for (usize idx = 0u; idx < 4u; ++idx) {
            const ArrayRef<u8> slice(msg.data(), lengths[idx]);
            auto padded_ct = aes_cbc_encrypt(key.as_ref(), iv.data(), slice);
            check_true("CBC PKCS#7 enc ok", padded_ct.has_value());
            if (padded_ct.has_value()) {
                auto unpadded = aes_cbc_decrypt(key.as_ref(), iv.data(), padded_ct->as_ref());
                check_true("CBC PKCS#7 dec ok", unpadded.has_value() && ct_equal(unpadded->as_ref(), slice));
                // Tamper last ciphertext byte -> padding check must fail
                Array<u8> bad = padded_ct->clone();
                bad[bad.size() - 1u] ^= 0x01u;
                check_true("CBC PKCS#7 bad pad", !aes_cbc_decrypt(key.as_ref(), iv.data(), bad.as_ref()).has_value());
            }
        }

        // NIST SP 800-38A F.5.1 CTR-AES128
        const Array<u8> ctr_iv = hex_bytes("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        const StringRef expected_ctr =
            "874d6191b620e3261bef6864990db6ce"
            "9806f66b7970fdff8617187bb9fffdff"
            "5ae4df3edbd5d35e5b4f09020db03eab"
            "1e031dda2fbe03d1792170a0f3009cee";
        Array<u8> ctr_out(msg.size(), u8{0u});
        check_true("CTR-128 enc ok", aes_ctr_xor(key.as_ref(), ctr_iv.data(), msg.as_ref(), ctr_out.as_mut_ref()));
        check_eq_str("NIST CTR-128 enc", to_hex(ctr_out.as_ref()).as_ref(), expected_ctr);
        // In-place decrypt
        check_true("CTR-128 dec in-place", aes_ctr_xor(key.as_ref(), ctr_iv.data(), ctr_out.as_ref(), ctr_out.as_mut_ref()));
        check_true("NIST CTR-128 dec", ct_equal(ctr_out.as_ref(), msg.as_ref()));
    }
}

void test_aes_gcm_nist() {
    auto check_gcm = [](StringRef label, StringRef key_hex, StringRef iv_hex,
                        StringRef aad_hex, StringRef pt_hex,
                        StringRef exp_ct_hex, StringRef exp_tag_hex) {
        const Array<u8> key = hex_bytes(key_hex);
        const Array<u8> iv = hex_bytes(iv_hex);
        const Array<u8> aad = hex_bytes(aad_hex);
        const Array<u8> pt = hex_bytes(pt_hex);
        Array<u8> ct(pt.size(), u8{0u});
        u8 tag[16] = {};

        check_true(label, aes_gcm_encrypt(key.as_ref(), iv.as_ref(), aad.as_ref(),
                                          pt.as_ref(), ct.as_mut_ref(), tag));
        check_eq_str(label, to_hex(ct.as_ref()).as_ref(), exp_ct_hex);
        check_eq_str(label, to_hex(ArrayRef<u8>(tag, 16u)).as_ref(), exp_tag_hex);

        Array<u8> dec(pt.size(), u8{0xAAu});
        check_true(label, aes_gcm_decrypt(key.as_ref(), iv.as_ref(), aad.as_ref(),
                                          ct.as_ref(), tag, dec.as_mut_ref()));
        check_true(label, ct_equal(dec.as_ref(), pt.as_ref()));

        // Tampered tag must fail and zero `dec`
        u8 bad_tag[16];
        mem_copy(bad_tag, tag, 16u);
        bad_tag[15] ^= 1u;
        for (usize i = 0u; i < dec.size(); ++i) dec[i] = 0x55u;
        check_true("GCM bad tag rejected",
                   !aes_gcm_decrypt(key.as_ref(), iv.as_ref(), aad.as_ref(),
                                    ct.as_ref(), bad_tag, dec.as_mut_ref()));
        bool all_zero = true;
        for (usize i = 0u; i < dec.size(); ++i) {
            if (dec[i] != 0u) all_zero = false;
        }
        check_true("GCM bad tag zeroes plaintext", all_zero);
    };

    // NIST GCM Test Case 1 (AES-128, empty PT, empty AAD)
    check_gcm("GCM TC1",
              "00000000000000000000000000000000",
              "000000000000000000000000",
              "", "", "",
              "58e2fccefa7e3061367f1d57a4e7455a");

    // NIST GCM Test Case 2 (AES-128, 16-byte zero PT, empty AAD)
    check_gcm("GCM TC2",
              "00000000000000000000000000000000",
              "000000000000000000000000",
              "",
              "00000000000000000000000000000000",
              "0388dace60b6a392f328c2b971b2fe78",
              "ab6e47d42cec13bdf53a67b21257bddf");

    // NIST GCM Test Case 4 (AES-128, 60-byte PT, 20-byte AAD, 12-byte IV)
    check_gcm("GCM TC4",
              "feffe9928665731c6d6a8f9467308308",
              "cafebabefacedbaddecaf888",
              "feedfacedeadbeeffeedfacedeadbeefabaddad2",
              "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
              "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
              "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
              "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
              "5bc94fbc3221a5db94fae95ae7121a47");

    // NIST GCM Test Case 5 (AES-128, 8-byte non-default IV -> GHASH J0 path)
    check_gcm("GCM TC5",
              "feffe9928665731c6d6a8f9467308308",
              "cafebabefacedbad",
              "feedfacedeadbeeffeedfacedeadbeefabaddad2",
              "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
              "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
              "61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c7423"
              "73806900e49f24b22b097544d4896b424989b5e1ebac0f07c23f4598",
              "3612d2e79e3b0785561be14aaca2fccb");

    // NIST GCM Test Case 6 (AES-128, 60-byte non-default IV)
    check_gcm("GCM TC6",
              "feffe9928665731c6d6a8f9467308308",
              "9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728"
              "c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b",
              "feedfacedeadbeeffeedfacedeadbeefabaddad2",
              "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
              "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
              "8ce24998625615b603a033aca13fb894be9112a5c3a211a8ba262a3cca7e2ca7"
              "01e4a9a4fba43c90ccdcb281d48c7c6fd62875d2aca417034c34aee5",
              "619cc5aefffe0bfa462af43c1699d050");

    // NIST GCM Test Case 10 (AES-192, 60-byte PT, 20-byte AAD, 12-byte IV)
    check_gcm("GCM TC10",
              "feffe9928665731c6d6a8f9467308308feffe9928665731c",
              "cafebabefacedbaddecaf888",
              "feedfacedeadbeeffeedfacedeadbeefabaddad2",
              "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
              "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
              "3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c"
              "7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710",
              "2519498e80f1478f37ba55bd6d27618c");

    // NIST GCM Test Case 16 (AES-256, 60-byte PT, 20-byte AAD, 12-byte IV)
    check_gcm("GCM TC16",
              "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
              "cafebabefacedbaddecaf888",
              "feedfacedeadbeeffeedfacedeadbeefabaddad2",
              "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
              "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
              "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
              "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
              "76fc6ece0f4e1768cddf8853bb2d551b");
}

void test_chacha20_poly1305_rfc8439() {
    // RFC 8439 §2.3.2 ChaCha20 block
    {
        const Array<u8> key = hex_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        const Array<u8> nonce = hex_bytes("000000090000004a00000000");
        u8 blk[64] = {};
        chacha20_block(key.data(), 1u, nonce.data(), blk);
        check_eq_str("RFC8439 ChaCha20 block",
                     to_hex(ArrayRef<u8>(blk, 64u)).as_ref(),
                     "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
                     "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e");
    }

    // RFC 8439 §2.4.2 ChaCha20 encryption
    {
        const Array<u8> key = hex_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        const Array<u8> nonce = hex_bytes("000000000000004a00000000");
        const StringRef msg =
            "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        const ArrayRef<u8> pt(reinterpret_cast<const u8*>(msg.data()), msg.size());
        Array<u8> ct(pt.size(), u8{0u});
        check_true("RFC8439 ChaCha20 xor", chacha20_xor(key.data(), 1u, nonce.data(), pt, ct.as_mut_ref()));
        check_eq_str("RFC8439 ChaCha20 ct", to_hex(ct.as_ref()).as_ref(),
                     "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b"
                     "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8"
                     "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736"
                     "5af90bbf74a35be6b40b8eedf2785e42874d");
    }

    // RFC 8439 §2.5.2 Poly1305
    {
        const Array<u8> key = hex_bytes("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
        const StringRef msg = "Cryptographic Forum Research Group";
        const ArrayRef<u8> bytes(reinterpret_cast<const u8*>(msg.data()), msg.size());
        const auto tag = Poly1305::mac(key.data(), bytes);
        check_eq_str("RFC8439 Poly1305", to_hex(tag.as_ref()).as_ref(),
                     "a8061dc1305136c6c22b8baf0c0127a9");
    }

    // RFC 8439 §2.8.2 ChaCha20-Poly1305 AEAD
    {
        const Array<u8> key = hex_bytes("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        const Array<u8> nonce = hex_bytes("070000004041424344454647");
        const Array<u8> aad = hex_bytes("50515253c0c1c2c3c4c5c6c7");
        const StringRef msg =
            "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        const ArrayRef<u8> pt(reinterpret_cast<const u8*>(msg.data()), msg.size());
        Array<u8> ct(pt.size(), u8{0u});
        u8 tag[16] = {};

        check_true("RFC8439 AEAD enc",
                   chacha20_poly1305_encrypt(key.data(), nonce.data(), aad.as_ref(),
                                             pt, ct.as_mut_ref(), tag));
        check_eq_str("RFC8439 AEAD ct", to_hex(ct.as_ref()).as_ref(),
                     "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
                     "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
                     "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
                     "3ff4def08e4b7a9de576d26586cec64b6116");
        check_eq_str("RFC8439 AEAD tag", to_hex(ArrayRef<u8>(tag, 16u)).as_ref(),
                     "1ae10b594f09e26a7e902ecbd0600691");

        Array<u8> dec(pt.size(), u8{0xAAu});
        check_true("RFC8439 AEAD dec",
                   chacha20_poly1305_decrypt(key.data(), nonce.data(), aad.as_ref(),
                                             ct.as_ref(), tag, dec.as_mut_ref()));
        check_true("RFC8439 AEAD pt match", ct_equal(dec.as_ref(), pt));

        // Tamper AAD -> decrypt must fail and wipe dec
        Array<u8> bad_aad = aad.clone();
        bad_aad[0] ^= 1u;
        check_true("RFC8439 AEAD bad AAD",
                   !chacha20_poly1305_decrypt(key.data(), nonce.data(), bad_aad.as_ref(),
                                              ct.as_ref(), tag, dec.as_mut_ref()));
        bool wiped = true;
        for (usize i = 0u; i < dec.size(); ++i) {
            if (dec[i] != 0u) wiped = false;
        }
        check_true("RFC8439 AEAD wipe on fail", wiped);
    }

    // draft-irtf-cfrg-xchacha §2.2.1 HChaCha20 & §A.3.1 XChaCha20-Poly1305
    {
        const Array<u8> key = hex_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        const Array<u8> nonce16 = hex_bytes("000000090000004a0000000031415927");
        u8 subkey[32] = {};
        hchacha20(key.data(), nonce16.data(), subkey);
        check_eq_str("HChaCha20 subkey", to_hex(ArrayRef<u8>(subkey, 32u)).as_ref(),
                     "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc");
    }
    {
        const Array<u8> key = hex_bytes("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        const Array<u8> nonce24 = hex_bytes("404142434445464748494a4b4c4d4e4f5051525354555657");
        const Array<u8> aad = hex_bytes("50515253c0c1c2c3c4c5c6c7");
        const StringRef msg =
            "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        const ArrayRef<u8> pt(reinterpret_cast<const u8*>(msg.data()), msg.size());
        Array<u8> ct(pt.size(), u8{0u});
        u8 tag[16] = {};

        check_true("XChaCha20-Poly1305 enc",
                   xchacha20_poly1305_encrypt(key.data(), nonce24.data(), aad.as_ref(),
                                              pt, ct.as_mut_ref(), tag));
        check_eq_str("XChaCha20-Poly1305 ct", to_hex(ct.as_ref()).as_ref(),
                     "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb"
                     "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452"
                     "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9"
                     "21f9664c97637da9768812f615c68b13b52e");
        check_eq_str("XChaCha20-Poly1305 tag", to_hex(ArrayRef<u8>(tag, 16u)).as_ref(),
                     "c0875924c1c7987947deafd8780acf49");

        Array<u8> dec(pt.size(), u8{0u});
        check_true("XChaCha20-Poly1305 dec",
                   xchacha20_poly1305_decrypt(key.data(), nonce24.data(), aad.as_ref(),
                                              ct.as_ref(), tag, dec.as_mut_ref()));
        check_true("XChaCha20-Poly1305 pt match", ct_equal(dec.as_ref(), pt));
    }
}

Optional<Array<u8>> parse_cli_hex(StringRef s) {
    if (s == "-") return Array<u8>{};
    return from_hex(s);
}

} // namespace

int main(int argc, char** argv) {
    // Optional CLI mode for cross-verification scripts:
    //   test_crypto --hash <alg> <hex_msg>
    //   test_crypto --hmac <alg> <hex_key> <hex_msg>
    //   test_crypto --aes-cbc-enc <hex_key> <hex_iv> <hex_pt>
    //   test_crypto --aes-ctr <hex_key> <hex_iv> <hex_in>
    //   test_crypto --aes-gcm-enc <hex_key> <hex_nonce> <hex_aad> <hex_pt>
    //   test_crypto --chacha20-poly1305-enc <hex_key> <hex_nonce> <hex_aad> <hex_pt>
    if (argc == 4 && StringRef(argv[1]) == "--hash") {
        auto d = Digest::create(StringRef(argv[2]));
        auto msg = parse_cli_hex(StringRef(argv[3]));
        if (!d.has_value() || !msg.has_value()) return 2;
        d->update(msg->as_ref());
        const String line = format("{}\n", to_hex(d->finalize().as_ref()));
        stdout_write(line.as_ref());
        return 0;
    }
    if (argc == 5 && StringRef(argv[1]) == "--hmac") {
        auto alg = parse_digest_algorithm(StringRef(argv[2]));
        auto key = parse_cli_hex(StringRef(argv[3]));
        auto msg = parse_cli_hex(StringRef(argv[4]));
        if (!alg.has_value() || !key.has_value() || !msg.has_value()) return 2;
        const String line = format("{}\n", to_hex(Hmac::compute(*alg, key->as_ref(), msg->as_ref()).as_ref()));
        stdout_write(line.as_ref());
        return 0;
    }
    if (argc == 5 && StringRef(argv[1]) == "--aes-cbc-enc") {
        auto key = parse_cli_hex(StringRef(argv[2]));
        auto iv = parse_cli_hex(StringRef(argv[3]));
        auto pt = parse_cli_hex(StringRef(argv[4]));
        if (!key.has_value() || !iv.has_value() || !pt.has_value() || iv->size() != 16u) return 2;
        auto ct = aes_cbc_encrypt(key->as_ref(), iv->data(), pt->as_ref());
        if (!ct.has_value()) return 3;
        const String line = format("{}\n", to_hex(ct->as_ref()));
        stdout_write(line.as_ref());
        return 0;
    }
    if (argc == 5 && StringRef(argv[1]) == "--aes-ctr") {
        auto key = parse_cli_hex(StringRef(argv[2]));
        auto iv = parse_cli_hex(StringRef(argv[3]));
        auto in = parse_cli_hex(StringRef(argv[4]));
        if (!key.has_value() || !iv.has_value() || !in.has_value() || iv->size() != 16u) return 2;
        Array<u8> out(in->size(), u8{0u});
        if (!aes_ctr_xor(key->as_ref(), iv->data(), in->as_ref(), out.as_mut_ref())) return 3;
        const String line = format("{}\n", to_hex(out.as_ref()));
        stdout_write(line.as_ref());
        return 0;
    }
    if (argc == 6 && StringRef(argv[1]) == "--aes-gcm-enc") {
        auto key = parse_cli_hex(StringRef(argv[2]));
        auto nonce = parse_cli_hex(StringRef(argv[3]));
        auto aad = parse_cli_hex(StringRef(argv[4]));
        auto pt = parse_cli_hex(StringRef(argv[5]));
        if (!key.has_value() || !nonce.has_value() || !aad.has_value() || !pt.has_value()) return 2;
        Array<u8> ct(pt->size(), u8{0u});
        u8 tag[16] = {};
        if (!aes_gcm_encrypt(key->as_ref(), nonce->as_ref(), aad->as_ref(),
                             pt->as_ref(), ct.as_mut_ref(), tag)) return 3;
        const String line = format("{} {}\n", to_hex(ct.as_ref()), to_hex(ArrayRef<u8>(tag, 16u)));
        stdout_write(line.as_ref());
        return 0;
    }
    if (argc == 6 && StringRef(argv[1]) == "--chacha20-poly1305-enc") {
        auto key = parse_cli_hex(StringRef(argv[2]));
        auto nonce = parse_cli_hex(StringRef(argv[3]));
        auto aad = parse_cli_hex(StringRef(argv[4]));
        auto pt = parse_cli_hex(StringRef(argv[5]));
        if (!key.has_value() || !nonce.has_value() || !aad.has_value() || !pt.has_value() ||
            key->size() != 32u || nonce->size() != 12u) return 2;
        Array<u8> ct(pt->size(), u8{0u});
        u8 tag[16] = {};
        if (!chacha20_poly1305_encrypt(key->data(), nonce->data(), aad->as_ref(),
                                       pt->as_ref(), ct.as_mut_ref(), tag)) return 3;
        const String line = format("{} {}\n", to_hex(ct.as_ref()), to_hex(ArrayRef<u8>(tag, 16u)));
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
    test_aes_fips197_and_modes();
    test_aes_gcm_nist();
    test_chacha20_poly1305_rfc8439();

    if (g_failures == 0) {
        stdout_write("ALL keel_crypto tests PASSED.\n");
        return 0;
    }
    const String summary = format("keel_crypto tests FAILED: {} failure(s).\n", g_failures);
    stderr_write(summary.as_ref());
    return 1;
}
