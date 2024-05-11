const std = @import("std");
const constants = @import("constants.zig");
const helpers = @import("helpers.zig");
const pkcs11 = @import("pkcs11.zig");

const Allocator = std.mem.Allocator;
const c = pkcs11.c;
const Context = pkcs11.Context;
const Error = constants.Error;

pub const SessionFlags = struct {
    read_write: bool = false,
    serial: bool = false,

    fn fromCType(flags: c.CK_FLAGS) SessionFlags {
        return .{
            .read_write = (flags & c.CKF_RW_SESSION) == c.CKF_RW_SESSION,
            .serial = (flags & c.CKF_SERIAL_SESSION) == c.CKF_SERIAL_SESSION,
        };
    }
};

pub const Session = struct {
    handle: *c.CK_SESSION_HANDLE,
    ctx: *Context,
    allocator: Allocator,

    /// Attempts to close the session with the PKCS#11 module.
    ///  - If the close succeeds, memory will be freed.
    ///  - If the close fails, no memory is freed since the session is technically still open.
    pub fn close(self: *Session) Error!void {
        const rv = self.ctx.sym.C_CloseSession.?(self.handle.*);
        try helpers.returnIfError(rv);
        self.deinit();
    }

    /// Frees allocated memory for this session without explicitly closing it.  This is useful after
    /// calling Module.closeAllSessions, since the Session.close method would fail for a session
    /// that has already been closed.
    pub fn deinit(self: *Session) void {
        self.allocator.destroy(self.handle);
        self.* = undefined;
    }
};
