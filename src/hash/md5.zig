const std = @import("std");
const mem = std.mem;
const math = std.math;

const state_length = 4;
// Starting state of the working variables in the algorithm
const default_initial_state = [state_length]u32{
    0x67452301,
    0xefcdab89,
    0x98badcfe,
    0x10325476,
};
const rounds = 64;
// bit shift to apply at each round
const shift = [rounds]u8{
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
};
// Round constants
const k = [rounds]u32{ 0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391 };

pub const Md5 = struct {
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
        return Self{ .h = default_initial_state };
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

        // Md5 uses the bottom 64-bits for length padding
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
        var i: usize = 1;
        var len = d.total_len >> 5;
        d.buf[56] = @as(u8, @intCast(d.total_len & 0x1f)) << 3;
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
        // a word size in md5 is 32 bits
        for (0..16) |i| {
            w[i] = mem.readInt(u32, block[i * 4 ..][0..4], .little);
        }

        var a = self.h[0];
        var b = self.h[1];
        var c = self.h[2];
        var d = self.h[3];

        for (0..rounds) |round| {
            var f: u32 = undefined;
            var g: u32 = undefined;
            const i: u32 = @intCast(round);

            switch (i) {
                0...15 => {
                    f = (b & c) | ((~b) & d);
                    g = i;
                },
                16...31 => {
                    f = (d & b) | ((~d) & c);
                    g = @mod(5 * i + 1, 16);
                },
                32...47 => {
                    f = b ^ c ^ d;
                    g = @mod(3 * i + 5, 16);
                },
                48...63 => {
                    f = c ^ (b | (~d));
                    g = @mod(7 * i, 16);
                },
                else => {},
            }

            f = f +% a +% k[i] +% w[g];
            a = d;
            d = c;
            c = b;
            b = b +% math.rotl(u32, f, shift[i]);
        }

        self.h[0] +%= a;
        self.h[1] +%= b;
        self.h[2] +%= c;
        self.h[3] +%= d;
    }
};

const htest = @import("test.zig");

test "single" {
    try htest.assertEqualHash(Md5, "d41d8cd98f00b204e9800998ecf8427e", "");
    try htest.assertEqualHash(Md5, "0cc175b9c0f1b6a831c399e269772661", "a");
    try htest.assertEqualHash(Md5, "900150983cd24fb0d6963f7d28e17f72", "abc");
    try htest.assertEqualHash(Md5, "f96b697d7cb7938d525a2f31aaf161d0", "message digest");
    try htest.assertEqualHash(Md5, "c3fcd3d76192e4007dfb496cca67e13b", "abcdefghijklmnopqrstuvwxyz");
    try htest.assertEqualHash(Md5, "d174ab98d277d9f5a5611c2c9f419d9f", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
    try htest.assertEqualHash(Md5, "57edf4a22be3c955ac49da2e2107b67a", "12345678901234567890123456789012345678901234567890123456789012345678901234567890");
}

test "streaming" {
    var h = Md5.init(.{});
    var out: [16]u8 = undefined;

    h.final(out[0..]);
    try htest.assertEqual("d41d8cd98f00b204e9800998ecf8427e", out[0..]);

    h = Md5.init(.{});
    h.update("abc");
    h.final(out[0..]);
    try htest.assertEqual("900150983cd24fb0d6963f7d28e17f72", out[0..]);

    h = Md5.init(.{});
    h.update("a");
    h.update("b");
    h.update("c");
    h.final(out[0..]);

    try htest.assertEqual("900150983cd24fb0d6963f7d28e17f72", out[0..]);
}

test "aligned final" {
    var block = [_]u8{0} ** Md5.block_length;
    var out: [Md5.digest_length]u8 = undefined;

    var h = Md5.init(.{});
    h.update(&block);
    h.final(out[0..]);
}
