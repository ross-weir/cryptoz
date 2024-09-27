/// Hash functions.
pub const hash = struct {
    pub const Sha1 = @import("hash/sha1.zig").Sha1;
};

test {
    _ = hash.Sha1;
}
