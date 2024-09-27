/// Hash functions.
pub const hash = struct {
    // TODO: use the exported Sha1 struct when it's added
    pub const Sha1 = @import("hash/sha1.zig").Sha1;
};

test {
    _ = hash.Sha1;
}
