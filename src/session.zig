const std = @import("std");
const err = @import("err.zig");
const helpers = @import("helpers.zig");
const pkcs11 = @import("pkcs11.zig");

const Allocator = std.mem.Allocator;
const C = pkcs11.C;
const Context = pkcs11.Context;
const Error = err.Error;

pub const Object = struct { handle: c_ulong };

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

pub const UserType = enum(c_ulong) {
    system_operator = C.CKU_SO,
    user = C.CKU_USER,
    context_specific = C.CKU_CONTEXT_SPECIFIC,
};

pub const SessionState = enum(c_ulong) {
    read_only_public = C.CKS_RO_PUBLIC_SESSION,
    read_only_user_functions = C.CKS_RO_USER_FUNCTIONS,
    read_write_public = C.CKS_RW_PUBLIC_SESSION,
    read_write_user_functions = C.CKS_RW_USER_FUNCTIONS,
    read_write_system_operator_functions = C.CKS_RW_SO_FUNCTIONS,
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

    /// Caller owns returned memory.
    pub fn getOperationState(self: Session, allocator: Allocator) Error![]u8 {
        var state_len: C.CK_ULONG = 0;
        var rv = self.ctx.sym.C_GetOperationState.?(self.handle, null, &state_len);
        try helpers.returnIfError(rv);

        const state = try allocator.alloc(u8, state_len);
        errdefer allocator.free(state);

        rv = self.ctx.sym.C_GetOperationState.?(self.handle, state.ptr, &state_len);
        try helpers.returnIfError(rv);

        return state;
    }

    pub fn setOperationState(self: Session, state: []u8, enc_key: ?Object, auth_key: ?Object) Error!void {
        var c_enc_key: c_ulong = 0;
        if (enc_key) |key| {
            c_enc_key = key.handle;
        }

        var c_auth_key: c_ulong = 0;
        if (auth_key) |key| {
            c_auth_key = key.handle;
        }

        const rv = self.ctx.sym.C_SetOperationState.?(self.handle, state.ptr, state.len, c_enc_key, c_auth_key);
        try helpers.returnIfError(rv);
    }
};
