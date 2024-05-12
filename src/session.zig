const std = @import("std");
const constants = @import("constants.zig");
const helpers = @import("helpers.zig");
const pkcs11 = @import("pkcs11.zig");

const Allocator = std.mem.Allocator;
const C = pkcs11.C;
const Context = pkcs11.Context;
const Error = constants.Error;
const SessionState = constants.SessionState;
const UserType = constants.UserType;

pub const SessionInfo = struct {
    slot_id: c_ulong,
    state: SessionState,
    flags: SessionFlags,
    device_error: c_ulong,

    fn fromCType(info: C.CK_SESSION_INFO) SessionInfo {
        return .{
            .slot_id = info.slotID,
            .state = @enumFromInt(info.state),
            .flags = SessionFlags.fromCType(info.flags),
            .device_error = info.ulDeviceError,
        };
    }
};

pub const SessionFlags = struct {
    read_write: bool = true,
    serial: bool = true,

    fn fromCType(flags: C.CK_FLAGS) SessionFlags {
        return .{
            .read_write = (flags & C.CKF_RW_SESSION) == C.CKF_RW_SESSION,
            .serial = (flags & C.CKF_SERIAL_SESSION) == C.CKF_SERIAL_SESSION,
        };
    }
};

pub const Session = struct {
    handle: C.CK_SESSION_HANDLE,
    ctx: *Context,

    pub fn close(self: *Session) Error!void {
        const rv = self.ctx.sym.C_CloseSession.?(self.handle);
        try helpers.returnIfError(rv);
    }

    pub fn initPIN(self: Session, pin: []const u8) Error!void {
        const rv = self.ctx.sym.C_InitPIN.?(self.handle, @constCast(pin.ptr), pin.len);
        try helpers.returnIfError(rv);
    }

    pub fn setPIN(self: Session, old_pin: []const u8, new_pin: []const u8) Error!void {
        const rv = self.ctx.sym.C_SetPIN.?(self.handle, @constCast(old_pin.ptr), old_pin.len, @constCast(new_pin.ptr), new_pin.len);
        try helpers.returnIfError(rv);
    }

    pub fn login(self: Session, user_type: UserType, pin: []const u8) Error!void {
        const rv = self.ctx.sym.C_Login.?(self.handle, @intFromEnum(user_type), @constCast(pin.ptr), pin.len);
        try helpers.returnIfError(rv);
    }

    pub fn logout(self: Session) Error!void {
        const rv = self.ctx.sym.C_Logout.?(self.handle);
        try helpers.returnIfError(rv);
    }

    pub fn getSessionInfo(self: Session) Error!SessionInfo {
        var info: C.CK_SESSION_INFO = undefined;
        const rv = self.ctx.sym.C_GetSessionInfo.?(self.handle, &info);
        try helpers.returnIfError(rv);

        return SessionInfo.fromCType(info);
    }
};
