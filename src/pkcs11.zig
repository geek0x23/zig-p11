const std = @import("std");

pub const c = @cImport({
    @cInclude("cryptoki.h");
});

pub const Context = struct {
    lib: std.DynLib,
    sym: *c.CK_FUNCTION_LIST,
};
