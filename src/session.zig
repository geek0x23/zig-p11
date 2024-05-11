const std = @import("std");
const constants = @import("constants.zig");
const helpers = @import("helpers.zig");
const pkcs11 = @import("pkcs11.zig");

const Allocator = std.mem.Allocator;
const c = pkcs11.c;
const Context = pkcs11.Context;
const Error = constants.Error;
const UserType = constants.UserType;

pub const SessionFlags = struct {
    read_write: bool = true,
    serial: bool = true,

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

    pub fn close(self: *Session) Error!void {
        const rv = self.ctx.sym.C_CloseSession.?(self.handle.*);
        try helpers.returnIfError(rv);
    }

    pub fn deinit(self: *Session) void {
        self.allocator.destroy(self.handle);
        self.* = undefined;
    }

    pub fn initPIN(self: Session, pin: []const u8) Error!void {
        const rv = self.ctx.sym.C_InitPIN.?(self.handle.*, @constCast(pin.ptr), pin.len);
        try helpers.returnIfError(rv);
    }

    pub fn login(self: Session, user_type: UserType, pin: []const u8) Error!void {
        const rv = self.ctx.sym.C_Login.?(self.handle.*, @intFromEnum(user_type), @constCast(pin.ptr), pin.len);
        try helpers.returnIfError(rv);
    }
};
