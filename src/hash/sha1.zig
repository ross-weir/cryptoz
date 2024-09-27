const std = @import("std");
const mem = std.mem;
const math = std.math;

// Round constants
const k = [4]u32{
    0x5a827999,
    0x6ed9eba1,
    0x8f1bbcdc,
    0xca62c1d6,
};

const state_length = 5;
// Starting state of the algorithm
const default_initial_state = [state_length]u32{ 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0 };

/// Compitable interface with std crypto hashers
/// in the context of the SHA1 paper they refer to a word size as 32bit, this can also be known as a dword when there is 16bit sizes
pub const Sha1 = struct {
    const Self = @This();
    /// Length of each block of the message input in bytes.
    pub const block_length = 64;
    /// Length of the output digest in bytes.
    pub const digest_length = 20;
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

    /// Initialize the hasher with custom initial state.
    /// This is useful for length extension attacks and not really anything else.
    /// That's why this method is private, it's only expected to be used in test cases/experimentation.
    fn restore(state: [state_length]u32, options: Options) Self {
        _ = options;
        return Self{ .h = state };
    }

    pub fn hash(message: []const u8, digest_out: *[digest_length]u8, options: Options) void {
        var hasher = Sha1.init(options);
        hasher.update(message);
        hasher.final(digest_out);
    }

    pub fn update(self: *Self, message: []const u8) void {
        var off: usize = 0;

        // Partial buffer exists from previous update. Copy into buffer then hash.
        if (self.buf_len != 0 and self.buf_len + message.len >= 64) {
            off += 64 - self.buf_len;
            @memcpy(self.buf[self.buf_len..][0..off], message[0..off]);

            self.compressBlock(self.buf[0..]);
            self.buf_len = 0;
        }

        // Full middle blocks.
        while (off + 64 <= message.len) : (off += 64) {
            self.compressBlock(message[off..][0..64]);
        }

        // Copy any remainder for next pass.
        @memcpy(self.buf[self.buf_len..][0 .. message.len - off], message[off..]);
        self.buf_len += @as(u8, @intCast(message[off..].len));

        self.total_len += message.len;
    }

    pub fn final(self: *Self, digest_out: *[digest_length]u8) void {
        // The buffer here will never be completely full.
        @memset(self.buf[self.buf_len..], 0);

        // Append padding bits.
        self.buf[self.buf_len] = 0x80;
        self.buf_len += 1;

        // > 448 mod 512 so need to add an extra round to wrap around.
        if (64 - self.buf_len < 8) {
            self.compressBlock(self.buf[0..]);
            @memset(self.buf[0..], 0);
        }

        // Append message length.
        var i: usize = 1;
        var len = self.total_len >> 5;
        self.buf[63] = @as(u8, @intCast(self.total_len & 0x1f)) << 3;
        while (i < 8) : (i += 1) {
            self.buf[63 - i] = @as(u8, @intCast(len & 0xff));
            len >>= 8;
        }

        self.compressBlock(self.buf[0..]);

        for (self.h, 0..) |s, j| {
            mem.writeInt(u32, digest_out[4 * j ..][0..4], s, .big);
        }
    }

    // todo: add reset method

    // Note: lots of room for optimizations, prepation/message scheduling could be interlaced into the 80 rounds
    // to prevent duplicate loops.
    //
    // Favouring readability so I can understand how the algorithm works.
    fn compressBlock(self: *Self, block: *const [block_length]u8) void {
        // block is divided into 16 chunks for processing
        // treated as a cirular buffer during message schedule for memory optimization
        var w: [16]u32 = undefined;

        for (0..16) |i| {
            w[i] = mem.readInt(u32, block[i * 4 ..][0..4], .big);
        }

        var a = self.h[0];
        var b = self.h[1];
        var c = self.h[2];
        var d = self.h[3];
        var e = self.h[4];
        var i: usize = 0;

        // In the below groups of 20 rounds the only thing that changes is the nonlinear function `f`.
        while (i < 20) : (i += 1) {
            if (i > 15) {
                const tmp = w[(i - 3) & 0xf] ^ w[(i - 8) & 0xf] ^ w[(i - 14) & 0xf] ^ w[(i - 16) & 0xf];
                w[i & 0xf] = math.rotl(u32, tmp, 1);
            }

            const f = (b & c) | (~b & d);
            const t = math.rotl(u32, a, 5) +% f +% e +% w[i & 0xf] +% k[0];

            e = d;
            d = c;
            c = math.rotl(u32, b, 30);
            b = a;
            a = t;
        }

        while (i < 40) : (i += 1) {
            const tmp = w[(i - 3) & 0xf] ^ w[(i - 8) & 0xf] ^ w[(i - 14) & 0xf] ^ w[(i - 16) & 0xf];
            w[i & 0xf] = math.rotl(u32, tmp, 1);

            const f = b ^ c ^ d;
            const t = math.rotl(u32, a, 5) +% f +% e +% w[i & 0xf] +% k[1];

            e = d;
            d = c;
            c = math.rotl(u32, b, 30);
            b = a;
            a = t;
        }

        while (i < 60) : (i += 1) {
            const tmp = w[(i - 3) & 0xf] ^ w[(i - 8) & 0xf] ^ w[(i - 14) & 0xf] ^ w[(i - 16) & 0xf];
            w[i & 0xf] = math.rotl(u32, tmp, 1);

            // alternative but equivalent expression for f()
            const f = (b & c) ^ (b & d) ^ (c & d);
            const t = math.rotl(u32, a, 5) +% f +% e +% w[i & 0xf] +% k[2];

            e = d;
            d = c;
            c = math.rotl(u32, b, 30);
            b = a;
            a = t;
        }

        while (i < 80) : (i += 1) {
            const tmp = w[(i - 3) & 0xf] ^ w[(i - 8) & 0xf] ^ w[(i - 14) & 0xf] ^ w[(i - 16) & 0xf];
            w[i & 0xf] = math.rotl(u32, tmp, 1);

            const f = b ^ c ^ d;
            const t = math.rotl(u32, a, 5) +% f +% e +% w[i & 0xf] +% k[3];

            e = d;
            d = c;
            c = math.rotl(u32, b, 30);
            b = a;
            a = t;
        }

        self.h[0] +%= a;
        self.h[1] +%= b;
        self.h[2] +%= c;
        self.h[3] +%= d;
        self.h[4] +%= e;
    }
};

const testing = std.testing;
const fmt = std.fmt;

// Hash using the specified hasher `H` asserting `expected == H(input)`.
pub fn assertEqualHash(comptime Hasher: anytype, comptime expected_hex: *const [Hasher.digest_length * 2:0]u8, input: []const u8) !void {
    var h: [Hasher.digest_length]u8 = undefined;
    Hasher.hash(input, &h, .{});

    try assertEqual(expected_hex, &h);
}

// Assert `expected` == hex(`input`) where `input` is a bytestring
pub fn assertEqual(comptime expected_hex: [:0]const u8, input: []const u8) !void {
    var expected_bytes: [expected_hex.len / 2]u8 = undefined;
    for (&expected_bytes, 0..) |*r, i| {
        r.* = fmt.parseInt(u8, expected_hex[2 * i .. 2 * i + 2], 16) catch unreachable;
    }

    try testing.expectEqualSlices(u8, &expected_bytes, input);
}

// have a restore method that allows restoring the state from an existing hash
// this will allow us to try length extension attacks
// explain how length ext attacks work & why certain outputs of SHA2 don't have the issue (because the truncate the output)

test "sha1 basic" {
    try assertEqualHash(Sha1, "da39a3ee5e6b4b0d3255bfef95601890afd80709", "");
    try assertEqualHash(Sha1, "a9993e364706816aba3e25717850c26c9cd0d89d", "abc");
    try assertEqualHash(Sha1, "a49b2446a02c645bf419f995b67091253a04a259", "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
}
