const std = @import("std");

pub const C = @cImport({
    @cInclude("pkcs11.h");
});

pub const Context = struct {
    lib: std.DynLib,
    sym: *C.CK_FUNCTION_LIST,
};
