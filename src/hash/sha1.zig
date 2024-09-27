const std = @import("std");

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

    state: [state_length]u32,

    pub fn init(options: Options) Self {
        _ = options;
        return Self{ .state = default_initial_state };
    }

    /// Initialize the hasher with custom initial state.
    /// This is useful for length extension attacks and not really anything else.
    /// That's why this method is private, it's only expected to be used in test cases/experimentation.
    fn restore(state: [state_length]u32, options: Options) Self {
        _ = options;
        return Self{ .state = state };
    }

    pub fn hash(message: []const u8, digest_out: *[digest_length]u8, options: Options) void {
        var hasher = Sha1.init(options);
        hasher.update(message);
        hasher.final(digest_out);
    }

    pub fn update(self: *Self, message: []const u8) void {
        _ = self;
        _ = message;
    }

    pub fn final(self: *Self, digest_out: *[digest_length]u8) void {
        _ = self;
        _ = digest_out;
    }

    // todo: add reset method

    fn compressBlock(self: *Self, block: *const [block_length]u8) void {
        // block is divided into 16 chunks for processing
        const chunks: [16]u32 = undefined;
        const active_state: [state_length]u32 = [_]u32{
            self.state[0],
            self.state[1],
            self.state[2],
            self.state[3],
            self.state[4],
        };

        _ = chunks;
        _ = block;

        self.state[0] +%= active_state[0];
        self.state[1] +%= active_state[1];
        self.state[2] +%= active_state[2];
        self.state[3] +%= active_state[3];
        self.state[4] +%= active_state[4];
    }
};

// have a restore method that allows restoring the state from an existing hash
// this will allow us to try length extension attacks
// explain how length ext attacks work & why certain outputs of SHA2 don't have the issue (because the truncate the output)

test "it runs at least" {
    var hasher = Sha1.init(.{});
    hasher.update(&[_]u8{ 1, 5, 3 });
}
