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
const rounds = 48;

const K2 = [_]u32{ 0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15 };
const K3 = [_]u32{ 0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15 };
const S1 = [_]u5{ 3, 7, 11, 19, 3, 7, 11, 19, 3, 7, 11, 19, 3, 7, 11, 19 };
const S2 = [_]u5{ 3, 5, 9, 13, 3, 5, 9, 13, 3, 5, 9, 13, 3, 5, 9, 13 };
const S3 = [_]u5{ 3, 9, 11, 15, 3, 9, 11, 15, 3, 9, 11, 15, 3, 9, 11, 15 };

// Historic and insecure crypograhpic hashing function.
// Implmented for educational purposes.
// DO NOT USE
pub const Md4 = struct {
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

        inline for (0..rounds) |i| {
            var t: u32 = undefined;

            switch (i) {
                0...15 => {
                    const f = (b & c) | (~b & d);
                    t = math.rotl(u32, a +% f +% w[i], S1[i]);
                },
                16...31 => {
                    const f = (b & c) | (b & d) | (c & d);
                    t = math.rotl(u32, a +% f +% w[K2[i & 0xf]] +% 0x5A827999, S2[i & 0xf]);
                },
                32...47 => {
                    const f = b ^ c ^ d;
                    t = math.rotl(u32, a +% f +% w[K3[i & 0xf]] +% 0x6ED9EBA1, S3[i & 0xf]);
                },
                else => {},
            }

            a = d;
            d = c;
            c = b;
            b = t;
        }

        self.h[0] +%= a;
        self.h[1] +%= b;
        self.h[2] +%= c;
        self.h[3] +%= d;
    }
};

const htest = @import("test.zig");

test "single" {
    try htest.assertEqualHash(Md4, "31d6cfe0d16ae931b73c59d7e0c089c0", "");
    try htest.assertEqualHash(Md4, "bde52cb31de33e46245e05fbdbd6fb24", "a");
    try htest.assertEqualHash(Md4, "a448017aaf21d8525fc10ae87aa6729d", "abc");
    try htest.assertEqualHash(Md4, "d9130a8164549fe818874806e1c7014b", "message digest");
    try htest.assertEqualHash(Md4, "d79e1c308aa5bbcdeea8ed63df412da9", "abcdefghijklmnopqrstuvwxyz");
    try htest.assertEqualHash(Md4, "043f8582f241db351ce627e153e7f0e4", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
    try htest.assertEqualHash(Md4, "e33b4ddc9c38f2199c3e7b164fcc0536", "12345678901234567890123456789012345678901234567890123456789012345678901234567890");
}

test "streaming" {
    var h = Md4.init(.{});
    var out: [16]u8 = undefined;

    h.final(out[0..]);
    try htest.assertEqual("31d6cfe0d16ae931b73c59d7e0c089c0", &out);

    h = Md4.init(.{});
    h.update("abc");
    h.final(out[0..]);
    try htest.assertEqual("a448017aaf21d8525fc10ae87aa6729d", &out);

    h = Md4.init(.{});
    h.update("a");
    h.update("b");
    h.update("c");
    h.final(out[0..]);
    try htest.assertEqual("a448017aaf21d8525fc10ae87aa6729d", &out);
}

test "aligned final" {
    var block = [_]u8{0} ** Md4.block_length;
    var out: [Md4.digest_length]u8 = undefined;

    var h = Md4.init(.{});
    h.update(&block);
    h.final(out[0..]);
}

