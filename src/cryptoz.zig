/// Hash functions.
pub const hash = struct {
    pub const Md4 = @import("hash/md4.zig").Md4;
    pub const Md5 = @import("hash/md5.zig").Md5;
    pub const Sha1 = @import("hash/sha1.zig").Sha1;
    pub const Ripemd128 = @import("hash/ripemd128.zig").Ripemd128;
};

test {
    _ = hash.Md4;
    _ = hash.Md5;
    _ = hash.Sha1;
    _ = hash.Ripemd128;
}
