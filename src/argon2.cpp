#include "keel/crypto/argon2.h"

#include "keel/crypto/blake.h"
#include "keel/crypto/ct.h"
#include "keel/memory.h"

namespace keel::crypto {

namespace {

constexpr u32 kArgon2Version = 0x13u;
constexpr usize kBlockU64s = 128u;
constexpr usize kBlockBytes = 1024u;
constexpr u32 kSyncPoints = 4u;

struct Block {
    u64 v[kBlockU64s];
};

constexpr void store_le32(u8* p, u32 v) noexcept {
    p[0] = as<u8>(v & 0xFFu);
    p[1] = as<u8>((v >> 8u) & 0xFFu);
    p[2] = as<u8>((v >> 16u) & 0xFFu);
    p[3] = as<u8>((v >> 24u) & 0xFFu);
}

constexpr u64 load_le64(const u8* p) noexcept {
    return as<u64>(p[0]) | (as<u64>(p[1]) << 8u) | (as<u64>(p[2]) << 16u) |
           (as<u64>(p[3]) << 24u) | (as<u64>(p[4]) << 32u) | (as<u64>(p[5]) << 40u) |
           (as<u64>(p[6]) << 48u) | (as<u64>(p[7]) << 56u);
}

constexpr void store_le64(u8* p, u64 v) noexcept {
    for (usize i = 0u; i < 8u; ++i) p[i] = as<u8>((v >> (i * 8u)) & 0xFFu);
}

constexpr u64 rotr64(u64 x, u32 n) noexcept {
    return (x >> n) | (x << (64u - n));
}

constexpr u64 fblamka(u64 x, u64 y) noexcept {
    const u64 m = 0xFFFFFFFFull;
    const u64 xy = (x & m) * (y & m);
    return x + y + 2ull * xy;
}

inline void gb(u64& a, u64& b, u64& c, u64& d) noexcept {
    a = fblamka(a, b);
    d = rotr64(d ^ a, 32u);
    c = fblamka(c, d);
    b = rotr64(b ^ c, 24u);
    a = fblamka(a, b);
    d = rotr64(d ^ a, 16u);
    c = fblamka(c, d);
    b = rotr64(b ^ c, 63u);
}

inline void blake2_round_16(u64& v0, u64& v1, u64& v2, u64& v3,
                            u64& v4, u64& v5, u64& v6, u64& v7,
                            u64& v8, u64& v9, u64& v10, u64& v11,
                            u64& v12, u64& v13, u64& v14, u64& v15) noexcept {
    gb(v0, v4, v8,  v12);
    gb(v1, v5, v9,  v13);
    gb(v2, v6, v10, v14);
    gb(v3, v7, v11, v15);
    gb(v0, v5, v10, v15);
    gb(v1, v6, v11, v12);
    gb(v2, v7, v8,  v13);
    gb(v3, v4, v9,  v14);
}

void compress_block(Block& out, const Block& x, const Block& y, bool xor_with_old) noexcept {
    Block r;
    Block z;
    for (usize i = 0u; i < kBlockU64s; ++i) {
        r.v[i] = x.v[i] ^ y.v[i];
        z.v[i] = r.v[i];
    }

    // Apply P row-wise (8 rows of 16 u64s)
    for (usize i = 0u; i < 8u; ++i) {
        const usize o = i * 16u;
        blake2_round_16(z.v[o + 0u],  z.v[o + 1u],  z.v[o + 2u],  z.v[o + 3u],
                        z.v[o + 4u],  z.v[o + 5u],  z.v[o + 6u],  z.v[o + 7u],
                        z.v[o + 8u],  z.v[o + 9u],  z.v[o + 10u], z.v[o + 11u],
                        z.v[o + 12u], z.v[o + 13u], z.v[o + 14u], z.v[o + 15u]);
    }

    // Apply P column-wise (8 columns of 8 pairs of u64s)
    for (usize i = 0u; i < 8u; ++i) {
        const usize c = i * 2u;
        blake2_round_16(z.v[c + 0u],   z.v[c + 1u],   z.v[c + 16u],  z.v[c + 17u],
                        z.v[c + 32u],  z.v[c + 33u],  z.v[c + 48u],  z.v[c + 49u],
                        z.v[c + 64u],  z.v[c + 65u],  z.v[c + 80u],  z.v[c + 81u],
                        z.v[c + 96u],  z.v[c + 97u],  z.v[c + 112u], z.v[c + 113u]);
    }

    if (xor_with_old) {
        for (usize i = 0u; i < kBlockU64s; ++i) out.v[i] ^= r.v[i] ^ z.v[i];
    } else {
        for (usize i = 0u; i < kBlockU64s; ++i) out.v[i] = r.v[i] ^ z.v[i];
    }
    secure_zero(&r, sizeof(r));
    secure_zero(&z, sizeof(z));
}

// RFC 9106 §3.3 variable-length hash function H'(in, out_len)
void blake2b_long(u8* out, usize out_len, ArrayRef<u8> in) noexcept {
    u8 len_le[4];
    store_le32(len_le, as<u32>(out_len));
    if (out_len <= 64u) {
        Blake2b b(out_len);
        b.update(len_le, 4u);
        b.update(in);
        b.finalize(out);
        return;
    }

    u8 v_buf[64];
    {
        Blake2b b(64u);
        b.update(len_le, 4u);
        b.update(in);
        b.finalize(v_buf);
    }
    mem_copy(out, v_buf, 32u);
    usize written = 32u;
    usize rem = out_len - 32u;

    while (rem > 64u) {
        Blake2b b(64u);
        b.update(v_buf, 64u);
        b.finalize(v_buf);
        mem_copy(out + written, v_buf, 32u);
        written += 32u;
        rem -= 32u;
    }

    Blake2b b(rem);
    b.update(v_buf, 64u);
    b.finalize(out + written);
    secure_zero(v_buf, sizeof(v_buf));
}

void next_addresses(Block& addr_block, Block& input_block, const Block& zero_block) noexcept {
    ++input_block.v[6];
    Block tmp{};
    compress_block(tmp, zero_block, input_block, false);
    compress_block(addr_block, zero_block, tmp, false);
    secure_zero(&tmp, sizeof(tmp));
}

u32 index_alpha(u32 pass, u32 slice, u32 index, u32 lane_length, u32 segment_length,
                bool same_lane, u32 pseudo_rand) noexcept {
    u32 ref_area_size = 0u;
    if (pass == 0u) {
        if (slice == 0u) {
            ref_area_size = index - 1u;
        } else if (same_lane) {
            ref_area_size = slice * segment_length + index - 1u;
        } else {
            ref_area_size = slice * segment_length - (index == 0u ? 1u : 0u);
        }
    } else {
        if (same_lane) {
            ref_area_size = lane_length - segment_length + index - 1u;
        } else {
            ref_area_size = lane_length - segment_length - (index == 0u ? 1u : 0u);
        }
    }

    u64 rel = as<u64>(pseudo_rand);
    rel = (rel * rel) >> 32u;
    rel = as<u64>(ref_area_size) - 1u - ((as<u64>(ref_area_size) * rel) >> 32u);

    const u32 start_pos = (pass != 0u && slice != kSyncPoints - 1u)
        ? (slice + 1u) * segment_length
        : 0u;
    return as<u32>((as<u64>(start_pos) + rel) % as<u64>(lane_length));
}

} // namespace

Optional<Array<u8>> argon2(const Argon2Params& params,
                           ArrayRef<u8> password,
                           ArrayRef<u8> salt,
                           ArrayRef<u8> secret,
                           ArrayRef<u8> associated_data,
                           Allocator* alloc) {
    if (params.parallelism == 0u || params.parallelism > 0x00FFFFFFu ||
        params.iterations == 0u || params.tag_len < 4u) {
        return Optional<Array<u8>>{};
    }
    if (as<u64>(params.memory_kib) < u64{8u} * as<u64>(params.parallelism)) {
        return Optional<Array<u8>>{};
    }
    constexpr u64 kMaxU32 = 0xFFFFFFFFull;
    if (as<u64>(password.size()) > kMaxU32 || as<u64>(salt.size()) > kMaxU32 ||
        as<u64>(secret.size()) > kMaxU32 || as<u64>(associated_data.size()) > kMaxU32) {
        return Optional<Array<u8>>{};
    }
    const u32 type_u32 = as<u32>(params.type);
    if (type_u32 > 2u) {
        return Optional<Array<u8>>{};
    }

    const u32 lanes = params.parallelism;
    const u32 segment_length = as<u32>(as<u64>(params.memory_kib) / (as<u64>(lanes) * as<u64>(kSyncPoints)));
    const u32 lane_length = segment_length * kSyncPoints;
    const u32 memory_blocks = lane_length * lanes;

    // 1. Compute H_0 = BLAKE2b-512(...)
    u8 h0[64];
    {
        Blake2b b(64u);
        u8 tmp[4];
        auto feed32 = [&](u32 x) {
            store_le32(tmp, x);
            b.update(tmp, 4u);
        };
        feed32(lanes);
        feed32(params.tag_len);
        feed32(params.memory_kib);
        feed32(params.iterations);
        feed32(kArgon2Version);
        feed32(type_u32);
        feed32(as<u32>(password.size()));
        if (!password.empty()) b.update(password);
        feed32(as<u32>(salt.size()));
        if (!salt.empty()) b.update(salt);
        feed32(as<u32>(secret.size()));
        if (!secret.empty()) b.update(secret);
        feed32(as<u32>(associated_data.size()));
        if (!associated_data.empty()) b.update(associated_data);
        b.finalize(h0);
    }

    // 2. Allocate memory_blocks 1024-byte blocks and fill first 2 blocks of each lane.
    Array<Block> mem(as<usize>(memory_blocks), Block{}, alloc);
    u8 seed_in[72];
    mem_copy(seed_in, h0, 64u);
    u8 raw_blk[kBlockBytes];
    for (u32 l = 0u; l < lanes; ++l) {
        store_le32(seed_in + 68u, l);
        for (u32 idx = 0u; idx < 2u; ++idx) {
            store_le32(seed_in + 64u, idx);
            blake2b_long(raw_blk, kBlockBytes, ArrayRef<u8>(seed_in, 72u));
            Block& dst = mem[as<usize>(l) * as<usize>(lane_length) + as<usize>(idx)];
            for (usize k = 0u; k < kBlockU64s; ++k) {
                dst.v[k] = load_le64(raw_blk + k * 8u);
            }
        }
    }
    secure_zero(h0, sizeof(h0));
    secure_zero(seed_in, sizeof(seed_in));
    secure_zero(raw_blk, sizeof(raw_blk));

    // 3. Fill memory across iterations, slices, and lanes.
    const Block zero_block{};
    Block addr_block{};
    Block input_block{};

    for (u32 pass = 0u; pass < params.iterations; ++pass) {
        for (u32 slice = 0u; slice < kSyncPoints; ++slice) {
            for (u32 lane = 0u; lane < lanes; ++lane) {
                const bool data_indep = (params.type == Argon2Type::Argon2i)
                    || (params.type == Argon2Type::Argon2id && pass == 0u && slice < 2u);
                if (data_indep) {
                    mem_zero(&input_block, sizeof(input_block));
                    input_block.v[0] = pass;
                    input_block.v[1] = lane;
                    input_block.v[2] = slice;
                    input_block.v[3] = memory_blocks;
                    input_block.v[4] = params.iterations;
                    input_block.v[5] = type_u32;
                }

                const u32 start_idx = (pass == 0u && slice == 0u) ? 2u : 0u;
                if (data_indep && start_idx == 2u) {
                    next_addresses(addr_block, input_block, zero_block);
                }

                const usize lane_base = as<usize>(lane) * as<usize>(lane_length);
                for (u32 idx = start_idx; idx < segment_length; ++idx) {
                    const u32 col = slice * segment_length + idx;
                    const u32 prev_col = (col == 0u) ? (lane_length - 1u) : (col - 1u);
                    const usize curr_off = lane_base + as<usize>(col);
                    const usize prev_off = lane_base + as<usize>(prev_col);

                    u64 pseudo_rand = 0u;
                    if (data_indep) {
                        if (idx % kBlockU64s == 0u) {
                            next_addresses(addr_block, input_block, zero_block);
                        }
                        pseudo_rand = addr_block.v[idx % kBlockU64s];
                    } else {
                        pseudo_rand = mem[prev_off].v[0];
                    }

                    const u32 j1 = as<u32>(pseudo_rand & 0xFFFFFFFFull);
                    const u32 j2 = as<u32>(pseudo_rand >> 32u);
                    const u32 ref_lane = (pass == 0u && slice == 0u) ? lane : (j2 % lanes);
                    const u32 ref_idx = index_alpha(pass, slice, idx, lane_length, segment_length,
                                                    ref_lane == lane, j1);
                    const Block& ref_blk = mem[as<usize>(ref_lane) * as<usize>(lane_length) + as<usize>(ref_idx)];
                    compress_block(mem[curr_off], mem[prev_off], ref_blk, pass > 0u);
                }
            }
        }
    }

    // 4. Finalize: XOR last block of every lane, serialize little-endian, apply H'.
    Block final_blk = mem[as<usize>(lane_length - 1u)];
    for (u32 l = 1u; l < lanes; ++l) {
        const Block& last = mem[as<usize>(l) * as<usize>(lane_length) + as<usize>(lane_length - 1u)];
        for (usize k = 0u; k < kBlockU64s; ++k) final_blk.v[k] ^= last.v[k];
    }
    u8 final_bytes[kBlockBytes];
    for (usize k = 0u; k < kBlockU64s; ++k) store_le64(final_bytes + k * 8u, final_blk.v[k]);

    Array<u8> tag(as<usize>(params.tag_len), u8{0u}, alloc);
    blake2b_long(tag.data(), tag.size(), ArrayRef<u8>(final_bytes, kBlockBytes));

    secure_zero(mem.data(), mem.size() * sizeof(Block));
    secure_zero(&final_blk, sizeof(final_blk));
    secure_zero(&addr_block, sizeof(addr_block));
    secure_zero(&input_block, sizeof(input_block));
    secure_zero(final_bytes, sizeof(final_bytes));
    return tag;
}

} // namespace keel::crypto
