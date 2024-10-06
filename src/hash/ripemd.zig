const std = @import("std");
const mem = std.mem;
const math = std.math;

const state_length = 4;
// Starting state of the working variables in the algorithm
const iv = [state_length]u32{ 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 };
const rounds = 64;

const k = [4]u32{ 0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc };
const k_p = [4]u32{ 0x50a28Be6, 0x5c4dd124, 0x6d703ef3, 0x00000000 };

const x = [rounds]u32{
    0, 1,  2,  3,  4,  5,  6,  7, 8,  9, 10, 11, 12, 13, 14, 15,
    7, 4,  13, 1,  10, 6,  15, 3, 12, 0, 9,  5,  2,  14, 11, 8,
    3, 10, 14, 4,  9,  15, 8,  1, 2,  7, 0,  6,  13, 11, 5,  12,
    1, 9,  11, 10, 0,  8,  12, 4, 13, 3, 7,  15, 14, 5,  6,  2,
};

const shift = [rounds]u32{
    11, 14, 15, 12, 5,  8,  7,  9,  11, 13, 14, 15, 6,  7,  9,  8,
    7,  6,  8,  13, 11, 9,  7,  15, 7,  12, 15, 9,  11, 7,  13, 12,
    11, 13, 6,  7,  14, 9,  13, 15, 14, 8,  13, 6,  5,  12, 7,  5,
    11, 12, 14, 15, 14, 15, 9,  8,  9,  14, 5,  6,  8,  6,  5,  12,
};

const x_p = [rounds]u32{
    5,  14, 7, 0, 9, 2,  11, 4,  13, 6,  15, 8,  1,  10, 3,  12,
    6,  11, 3, 7, 0, 13, 5,  10, 14, 15, 8,  12, 4,  9,  1,  2,
    15, 5,  1, 3, 7, 14, 6,  9,  11, 8,  12, 2,  10, 0,  4,  13,
    8,  6,  4, 1, 3, 11, 15, 0,  5,  12, 2,  13, 9,  7,  10, 14,
};

const shift_p = [rounds]u32{
    8,  9,  9,  11, 13, 15, 15, 5,  7,  7,  8,  11, 14, 14, 12, 6,
    9,  13, 15, 7,  12, 8,  9,  11, 7,  7,  12, 7,  6,  15, 13, 11,
    9,  7,  15, 11, 8,  6,  6,  14, 12, 13, 5,  14, 13, 13, 7,  5,
    15, 5,  8,  11, 14, 14, 6,  14, 6,  9,  12, 9,  12, 5,  15, 8,
};

pub const Ripemd128 = struct {
    const Self = @This();
    /// Length of each block of the message input in bytes.
    pub const block_length = 64;
    /// Length of the output digest in bytes.
    pub const digest_length = 16;
    pub const Options = struct {};

    h: [state_length]u32,
    // Streaming Cache
    buf: [64]u8 = undefined,
    buf_len: u8 = 0,
    total_len: u64 = 0,

    pub fn init(options: Options) Self {
        _ = options;
        return Self{ .h = iv };
    }

    pub fn hash(message: []const u8, digest_out: *[digest_length]u8, options: Options) void {
        var hasher = Self.init(options);
        hasher.update(message);
        hasher.final(digest_out);
    }

    pub fn update(d: *Self, b: []const u8) void {
        var off: usize = 0;

        // Partial buffer exists from previous update. Copy into buffer then hash.
        if (d.buf_len != 0 and d.buf_len + b.len >= 64) {
            off += 64 - d.buf_len;
            @memcpy(d.buf[d.buf_len..][0..off], b[0..off]);

            d.compressBlock(&d.buf);
            d.buf_len = 0;
        }

        // Full middle blocks.
        while (off + 64 <= b.len) : (off += 64) {
            d.compressBlock(b[off..][0..64]);
        }

        // Copy any remainder for next pass.
        const b_slice = b[off..];
        @memcpy(d.buf[d.buf_len..][0..b_slice.len], b_slice);
        d.buf_len += @as(u8, @intCast(b_slice.len));

        d.total_len +%= b.len;
    }

    pub fn final(d: *Self, out: *[digest_length]u8) void {
        // The buffer here will never be completely full.
        @memset(d.buf[d.buf_len..], 0);

        // Append padding bits.
        d.buf[d.buf_len] = 0x80;
        d.buf_len += 1;

        // > 448 mod 512 so need to add an extra round to wrap around.
        if (64 - d.buf_len < 8) {
            d.compressBlock(d.buf[0..]);
            @memset(d.buf[0..], 0);
        }

        // Append message length.
        var i: usize = 0;
        var len = d.total_len << 3;
        while (i < 8) : (i += 1) {
            d.buf[56 + i] = @as(u8, @intCast(len & 0xff));
            len >>= 8;
        }

        d.compressBlock(d.buf[0..]);

        for (d.h, 0..) |s, j| {
            mem.writeInt(u32, out[4 * j ..][0..4], s, .little);
        }
    }

    fn compressBlock(self: *Self, block: *const [block_length]u8) void {
        var w: [16]u32 = undefined;

        // divide the block into 16 words
        // a word size in md4 is 32 bits
        for (0..16) |i| {
            w[i] = mem.readInt(u32, block[i * 4 ..][0..4], .little);
        }

        var a = self.h[0];
        var b = self.h[1];
        var c = self.h[2];
        var d = self.h[3];

        // parralell variables
        var aa = a;
        var bb = b;
        var cc = c;
        var dd = d;

        inline for (0..rounds) |round| {
            const i: u32 = @intCast(round);
            // boolean func results
            var f: u32 = undefined;
            var f_p: u32 = undefined;

            switch (i) {
                0...15 => {
                    const k_idx = 0;

                    f = a +% (b ^ c ^ d) +% w[x[i]] +% k[k_idx];
                    f_p = aa +% (cc ^ (dd & (bb ^ cc))) +% w[x_p[i]] +% k_p[k_idx];
                },
                16...31 => {
                    const k_idx = 1;

                    f = a +% ((b & c) | (~b & d)) +% w[x[i]] +% k[k_idx];
                    f_p = aa +% (dd ^ (bb | ~cc)) +% w[x_p[i]] +% k_p[k_idx];
                },
                32...47 => {
                    const k_idx = 2;

                    f = a +% (d ^ (b | ~c)) +% w[x[i]] +% k[k_idx];
                    f_p = aa +% (dd ^ (bb & (cc ^ dd))) +% w[x_p[i]] +% k_p[k_idx];
                },
                48...63 => {
                    const k_idx = 3;

                    f = a +% ((b & c) | (c & ~d)) +% w[x[i]] +% k[k_idx];
                    f_p = aa +% (bb ^ cc ^ dd) +% w[x_p[i]] +% k_p[k_idx];
                },
                else => {},
            }

            a = d;
            d = c;
            c = b;
            b = math.rotl(u32, f, shift[i]);

            aa = dd;
            dd = cc;
            cc = bb;
            bb = math.rotl(u32, f_p, shift_p[i]);
        }

        c = self.h[1] +% c +% dd;
        self.h[1] = self.h[2] +% d +% aa;
        self.h[2] = self.h[3] +% a +% bb;
        self.h[3] = self.h[0] +% b +% cc;
        self.h[0] = c;
    }
};

const htest = @import("test.zig");

test "single" {
    try htest.assertEqualHash(Ripemd128, "cdf26213a150dc3ecb610f18f6b38b46", "");
    // try htest.assertEqualHash(Ripemd128, "86be7afa339d0fc7cfc785e72f578d33", "a");
    // try htest.assertEqualHash(Ripemd128, "c14a12199c66e4ba84636b0f69144c77", "abc");
    // try htest.assertEqualHash(Ripemd128, "9e327b3d6e523062afc1132d7df9d1b8", "message digest");
    // try htest.assertEqualHash(Ripemd128, "fd2aa607f71dc8f510714922b371834e", "abcdefghijklmnopqrstuvwxyz");
    // try htest.assertEqualHash(Ripemd128, "a1aa0689d0fafa2ddc22e88b49133a06", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
    // try htest.assertEqualHash(Ripemd128, "d1e959eb179c911faea4624c60c5c702", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
}
