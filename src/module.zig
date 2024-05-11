const std = @import("std");
const builtin = @import("builtin");
const config = @import("config");
const pkcs11 = @import("pkcs11.zig");
const constants = @import("constants.zig");
const helpers = @import("helpers.zig");
const session = @import("session.zig");

const c = pkcs11.c;
const Allocator = std.mem.Allocator;
const Context = pkcs11.Context;
const Error = constants.Error;
const MechanismType = constants.MechanismType;
const ReturnValue = constants.ReturnValue;
const Session = session.Session;
const SessionFlags = session.SessionFlags;
const UserType = constants.UserType;

pub const Version = struct {
    major: u8,
    minor: u8,

    fn fromCType(version: c.CK_VERSION) Version {
        return .{ .major = version.major, .minor = version.minor };
    }
};

pub const SlotInfo = struct {
    description: [64]u8,
    manufacturer_id: [32]u8,
    flags: SlotFlags,
    hardware_version: Version,
    firmware_version: Version,

    fn fromCType(info: c.CK_SLOT_INFO) SlotInfo {
        return .{
            .description = info.slotDescription,
            .manufacturer_id = info.manufacturerID,
            .flags = SlotFlags.fromCType(info.flags),
            .hardware_version = Version.fromCType(info.hardwareVersion),
            .firmware_version = Version.fromCType(info.firmwareVersion),
        };
    }
};

pub const SlotFlags = struct {
    token_present: bool = false,
    removable_device: bool = false,
    hardware_slot: bool = false,

    fn fromCType(flags: c.CK_FLAGS) SlotFlags {
        return .{
            .hardware_slot = (flags & c.CKF_HW_SLOT) == c.CKF_HW_SLOT,
            .removable_device = (flags & c.CKF_REMOVABLE_DEVICE) == c.CKF_REMOVABLE_DEVICE,
            .token_present = (flags & c.CKF_TOKEN_PRESENT) == c.CKF_TOKEN_PRESENT,
        };
    }
};

pub const Info = struct {
    cryptoki_version: Version,
    manufacturer_id: [32]u8,
    /// Per the PKCS#11 spec, this field is always zero.
    flags: u8 = 0,
    library_description: [32]u8,
    library_version: Version,

    fn fromCType(info: c.CK_INFO) Info {
        return .{
            .manufacturer_id = info.manufacturerID,
            .library_description = info.libraryDescription,
            .cryptoki_version = Version.fromCType(info.cryptokiVersion),
            .library_version = Version.fromCType(info.libraryVersion),
        };
    }
};

pub const TokenInfo = struct {
    label: [32]u8,
    manufacturer_id: [32]u8,
    model: [16]u8,
    serial_number: [16]u8,
    flags: TokenFlags,
    max_session_count: c_ulong,
    session_count: c_ulong,
    max_rw_session_count: c_ulong,
    rw_session_count: c_ulong,
    max_pin_len: c_ulong,
    min_pin_len: c_ulong,
    total_public_memory: c_ulong,
    free_public_memory: c_ulong,
    total_private_memory: c_ulong,
    free_private_memory: c_ulong,
    hardware_version: Version,
    firmware_version: Version,
    utc_time: [16]u8,

    fn fromCType(info: c.CK_TOKEN_INFO) TokenInfo {
        return .{
            .label = info.label,
            .manufacturer_id = info.manufacturerID,
            .model = info.model,
            .serial_number = info.serialNumber,
            .flags = TokenFlags.fromCType(info.flags),
            .max_session_count = info.ulMaxSessionCount,
            .session_count = info.ulSessionCount,
            .max_rw_session_count = info.ulMaxRwSessionCount,
            .rw_session_count = info.ulRwSessionCount,
            .max_pin_len = info.ulMaxPinLen,
            .min_pin_len = info.ulMinPinLen,
            .total_public_memory = info.ulTotalPublicMemory,
            .free_public_memory = info.ulFreePublicMemory,
            .total_private_memory = info.ulTotalPrivateMemory,
            .free_private_memory = info.ulFreePrivateMemory,
            .hardware_version = Version.fromCType(info.hardwareVersion),
            .firmware_version = Version.fromCType(info.firmwareVersion),
            .utc_time = info.utcTime,
        };
    }
};

pub const TokenFlags = struct {
    rng: bool = false,
    write_protected: bool = false,
    login_required: bool = false,
    user_pin_initialized: bool = false,
    restore_key_not_needed: bool = false,
    clock_on_token: bool = false,
    protected_authentication_path: bool = false,
    dual_crypto_operations: bool = false,
    token_initialized: bool = false,
    secondary_authentication: bool = false,
    user_pin_count_low: bool = false,
    user_pin_final_try: bool = false,
    user_pin_locked: bool = false,
    user_pin_to_be_changed: bool = false,
    so_pin_count_low: bool = false,
    so_pin_final_try: bool = false,
    so_pin_locked: bool = false,
    so_pin_to_be_changed: bool = false,
    error_state: bool = false,

    fn fromCType(flags: c.CK_FLAGS) TokenFlags {
        return .{
            .rng = (flags & c.CKF_RNG) == c.CKF_RNG,
            .write_protected = (flags & c.CKF_WRITE_PROTECTED) == c.CKF_WRITE_PROTECTED,
            .login_required = (flags & c.CKF_LOGIN_REQUIRED) == c.CKF_LOGIN_REQUIRED,
            .user_pin_initialized = (flags & c.CKF_USER_PIN_INITIALIZED) == c.CKF_USER_PIN_INITIALIZED,
            .restore_key_not_needed = (flags & c.CKF_RESTORE_KEY_NOT_NEEDED) == c.CKF_RESTORE_KEY_NOT_NEEDED,
            .clock_on_token = (flags & c.CKF_CLOCK_ON_TOKEN) == c.CKF_CLOCK_ON_TOKEN,
            .protected_authentication_path = (flags & c.CKF_PROTECTED_AUTHENTICATION_PATH) == c.CKF_PROTECTED_AUTHENTICATION_PATH,
            .dual_crypto_operations = (flags & c.CKF_DUAL_CRYPTO_OPERATIONS) == c.CKF_DUAL_CRYPTO_OPERATIONS,
            .token_initialized = (flags & c.CKF_TOKEN_INITIALIZED) == c.CKF_TOKEN_INITIALIZED,
            .secondary_authentication = (flags & c.CKF_SECONDARY_AUTHENTICATION) == c.CKF_SECONDARY_AUTHENTICATION,
            .user_pin_count_low = (flags & c.CKF_USER_PIN_COUNT_LOW) == c.CKF_USER_PIN_COUNT_LOW,
            .user_pin_final_try = (flags & c.CKF_USER_PIN_FINAL_TRY) == c.CKF_USER_PIN_FINAL_TRY,
            .user_pin_locked = (flags & c.CKF_USER_PIN_LOCKED) == c.CKF_USER_PIN_LOCKED,
            .user_pin_to_be_changed = (flags & c.CKF_USER_PIN_TO_BE_CHANGED) == c.CKF_USER_PIN_TO_BE_CHANGED,
            .so_pin_count_low = (flags & c.CKF_SO_PIN_COUNT_LOW) == c.CKF_SO_PIN_COUNT_LOW,
            .so_pin_final_try = (flags & c.CKF_SO_PIN_FINAL_TRY) == c.CKF_SO_PIN_FINAL_TRY,
            .so_pin_locked = (flags & c.CKF_SO_PIN_LOCKED) == c.CKF_SO_PIN_LOCKED,
            .so_pin_to_be_changed = (flags & c.CKF_SO_PIN_TO_BE_CHANGED) == c.CKF_SO_PIN_TO_BE_CHANGED,
            .error_state = (flags & c.CKF_ERROR_STATE) == c.CKF_ERROR_STATE,
        };
    }
};

pub const MechanismInfo = struct {
    min_key_size: c_ulong,
    max_key_size: c_ulong,
    flags: MechanismFlags,

    fn fromCType(info: c.CK_MECHANISM_INFO) MechanismInfo {
        return .{
            .min_key_size = info.ulMinKeySize,
            .max_key_size = info.ulMaxKeySize,
            .flags = MechanismFlags.fromCType(info.flags),
        };
    }
};

pub const MechanismFlags = struct {
    hardware: bool = false,
    encrypt: bool = false,
    decrypt: bool = false,
    digest: bool = false,
    sign: bool = false,
    sign_with_recovery: bool = false,
    verify: bool = false,
    verify_with_recovery: bool = false,
    generate: bool = false,
    generate_key_pair: bool = false,
    wrap: bool = false,
    unwrap: bool = false,
    derive: bool = false,
    ec: MechanismECFlags,
    extension: bool = false,

    fn fromCType(flags: c.CK_FLAGS) MechanismFlags {
        return .{
            .hardware = (flags & c.CKF_HW) == c.CKF_HW,
            .encrypt = (flags & c.CKF_ENCRYPT) == c.CKF_ENCRYPT,
            .decrypt = (flags & c.CKF_DECRYPT) == c.CKF_DECRYPT,
            .digest = (flags & c.CKF_DIGEST) == c.CKF_DIGEST,
            .sign = (flags & c.CKF_SIGN) == c.CKF_SIGN,
            .sign_with_recovery = (flags & c.CKF_SIGN_RECOVER) == c.CKF_SIGN_RECOVER,
            .verify = (flags & c.CKF_VERIFY) == c.CKF_VERIFY,
            .verify_with_recovery = (flags & c.CKF_VERIFY_RECOVER) == c.CKF_VERIFY_RECOVER,
            .generate = (flags & c.CKF_GENERATE) == c.CKF_GENERATE,
            .generate_key_pair = (flags & c.CKF_GENERATE_KEY_PAIR) == c.CKF_GENERATE_KEY_PAIR,
            .wrap = (flags & c.CKF_WRAP) == c.CKF_WRAP,
            .unwrap = (flags & c.CKF_UNWRAP) == c.CKF_UNWRAP,
            .derive = (flags & c.CKF_DERIVE) == c.CKF_DERIVE,
            .ec = MechanismECFlags.fromCType(flags),
            .extension = (flags & c.CKF_EXTENSION) == c.CKF_EXTENSION,
        };
    }
};

pub const MechanismECFlags = struct {
    f_p: bool = false,
    f_2m: bool = false,
    parameters: bool = false,
    named_curve: bool = false,
    uncompress: bool = false,
    compress: bool = false,

    fn fromCType(flags: c.CK_FLAGS) MechanismECFlags {
        return .{
            .f_p = (flags & c.CKF_EC_F_P) == c.CKF_EC_F_P,
            .f_2m = (flags & c.CKF_EC_F_2M) == c.CKF_EC_F_2M,
            .parameters = (flags & c.CKF_EC_ECPARAMETERS) == c.CKF_EC_ECPARAMETERS,
            .named_curve = (flags & c.CKF_EC_NAMEDCURVE) == c.CKF_EC_NAMEDCURVE,
            .uncompress = (flags & c.CKF_EC_UNCOMPRESS) == c.CKF_EC_UNCOMPRESS,
            .compress = (flags & c.CKF_EC_COMPRESS) == c.CKF_EC_COMPRESS,
        };
    }
};

pub const Module = struct {
    ctx: *Context,
    allocator: Allocator,

    /// Caller must deinit() to close the library and free memory.
    /// Opens the given PKCS#11 library and loads symbols from it.
    pub fn init(alloc: Allocator, path: []const u8) !Module {
        var lib = try std.DynLib.open(path);

        const context = try alloc.create(Context);
        context.lib = lib;

        const getFunctionList = lib.lookup(c.CK_C_GetFunctionList, "C_GetFunctionList").?.?;
        const rv = getFunctionList(@ptrCast(&context.sym));
        try helpers.returnIfError(rv);

        return .{ .allocator = alloc, .ctx = context };
    }

    /// Closes the PKCS#11 library and frees memory.
    pub fn deinit(self: *Module) void {
        self.ctx.lib.close();
        self.allocator.destroy(self.ctx);
        self.* = undefined;
    }

    pub fn initialize(self: Module) Error!void {
        var args: c.CK_C_INITIALIZE_ARGS = .{ .flags = c.CKF_OS_LOCKING_OK };
        const rv = self.ctx.sym.C_Initialize.?(&args);
        try helpers.returnIfError(rv);
    }

    pub fn finalize(self: Module) Error!void {
        const args: c.CK_VOID_PTR = null;
        const rv = self.ctx.sym.C_Finalize.?(args);
        try helpers.returnIfError(rv);
    }

    /// Caller owns returned memory.
    pub fn getInfo(self: Module) Error!Info {
        var info: c.CK_INFO = undefined;
        const rv = self.ctx.sym.C_GetInfo.?(&info);
        try helpers.returnIfError(rv);

        return Info.fromCType(info);
    }

    /// Caller owns returned memory.
    pub fn getSlotList(self: Module, token_present: bool) Error![]c_ulong {
        const present: c.CK_BBOOL = if (token_present) c.CK_TRUE else c.CK_FALSE;
        var slot_count: c.CK_ULONG = undefined;

        var rv = self.ctx.sym.C_GetSlotList.?(present, null, &slot_count);
        try helpers.returnIfError(rv);

        const slot_list = try self.allocator.alloc(c.CK_ULONG, slot_count);
        rv = self.ctx.sym.C_GetSlotList.?(present, slot_list.ptr, &slot_count);
        try helpers.returnIfError(rv);

        return slot_list;
    }

    pub fn getSlotInfo(self: Module, slot_id: c_ulong) Error!SlotInfo {
        var slot_info: c.CK_SLOT_INFO = undefined;
        const rv = self.ctx.sym.C_GetSlotInfo.?(slot_id, &slot_info);
        try helpers.returnIfError(rv);

        return SlotInfo.fromCType(slot_info);
    }

    pub fn getTokenInfo(self: Module, slot_id: c_ulong) Error!TokenInfo {
        var token_info: c.CK_TOKEN_INFO = undefined;
        const rv = self.ctx.sym.C_GetTokenInfo.?(slot_id, &token_info);
        try helpers.returnIfError(rv);

        return TokenInfo.fromCType(token_info);
    }

    /// Caller owns returned memory.
    pub fn getMechanismList(self: Module, slot_id: c_ulong) Error![]MechanismType {
        var mech_count: c.CK_ULONG = undefined;

        var rv = self.ctx.sym.C_GetMechanismList.?(slot_id, null, &mech_count);
        try helpers.returnIfError(rv);

        const mech_list = try self.allocator.alloc(MechanismType, mech_count);
        rv = self.ctx.sym.C_GetMechanismList.?(slot_id, @ptrCast(mech_list.ptr), &mech_count);
        try helpers.returnIfError(rv);

        return mech_list;
    }

    pub fn getMechanismInfo(self: Module, slot_id: c_ulong, mech_type: MechanismType) Error!MechanismInfo {
        var mech_info: c.CK_MECHANISM_INFO = undefined;
        const rv = self.ctx.sym.C_GetMechanismInfo.?(slot_id, @intFromEnum(mech_type), &mech_info);
        try helpers.returnIfError(rv);

        return MechanismInfo.fromCType(mech_info);
    }

    /// Per the PKCS#11 Spec:
    ///  - If label is more than 32 bytes, it will be truncated.
    ///  - If label is less than 32 bytes, it will be padded with spaces.
    pub fn initToken(self: Module, slot_id: c_ulong, pin: []const u8, label: []const u8) Error!void {
        var padded_label = [_:0]u8{0x20} ** 32;
        const n = @min(padded_label.len, label.len);
        for (0..n) |i| {
            padded_label[i] = label[i];
        }

        const rv = self.ctx.sym.C_InitToken.?(slot_id, @constCast(pin.ptr), pin.len, &padded_label);
        try helpers.returnIfError(rv);
    }

    /// When a session is opened, the underlying handle is allocated.
    /// Caller must call Session.deinit to free memory.
    pub fn openSession(self: Module, slot_id: c_ulong, flags: SessionFlags) Error!Session {
        var packed_flags: c_ulong = 0;
        if (flags.read_write) {
            packed_flags = packed_flags | c.CKF_RW_SESSION;
        }
        if (flags.serial) {
            packed_flags = packed_flags | c.CKF_SERIAL_SESSION;
        }

        // We're *NOT* supporting Notify/Callback setups here on purpose.
        const handle = try self.allocator.create(c.CK_SESSION_HANDLE);
        const rv = self.ctx.sym.C_OpenSession.?(slot_id, packed_flags, null, null, handle);
        try helpers.returnIfError(rv);

        return .{
            .handle = handle,
            .allocator = self.allocator,
            .ctx = self.ctx,
        };
    }

    pub fn closeAllSessions(self: Module, slot_id: c_ulong) Error!void {
        const rv = self.ctx.sym.C_CloseAllSessions.?(slot_id);
        try helpers.returnIfError(rv);
    }
};

const testing = std.testing;

test "it can load a PKCS#11 module." {
    var mod = try Module.init(testing.allocator, config.module);
    defer mod.deinit();
}

test "it can initialize and finalize the module." {
    var mod = try Module.init(testing.allocator, config.module);
    defer mod.deinit();

    try mod.initialize();
    try mod.finalize();
}

test "it can get all the infos" {
    const allocator = testing.allocator;
    var mod = try Module.init(allocator, config.module);
    defer mod.deinit();
    try mod.initialize();

    const slots = try mod.getSlotList(true);
    defer allocator.free(slots);
    try testing.expect(slots.len > 0);
    const slot = slots[0];

    const slot_info = try mod.getSlotInfo(slot);
    try testing.expectStringStartsWith(&slot_info.description, "SoftHSM");
    try testing.expect(slot_info.flags.token_present);

    const info = try mod.getInfo();
    try testing.expectStringStartsWith(&info.manufacturer_id, "SoftHSM");

    const token_info = try mod.getTokenInfo(slot);
    try testing.expectStringStartsWith(&token_info.manufacturer_id, "SoftHSM");

    const mechs = try mod.getMechanismList(slot);
    defer allocator.free(mechs);
    try testing.expect(mechs.len > 0);

    var mech_info = try mod.getMechanismInfo(slot, MechanismType.aes_cbc);
    try testing.expect(mech_info.flags.encrypt);
    try testing.expect(mech_info.flags.decrypt);

    mech_info = try mod.getMechanismInfo(slot, MechanismType.ec_key_pair_gen);
    try testing.expect(mech_info.flags.generate_key_pair);
    try testing.expect(mech_info.flags.ec.named_curve);
    try testing.expect(mech_info.flags.ec.uncompress);

    try mod.finalize();
}

test "it can initialize a new token" {
    const allocator = testing.allocator;
    var mod = try Module.init(allocator, config.module);
    defer mod.deinit();
    try mod.initialize();
    defer mod.finalize() catch {};

    const slots = try mod.getSlotList(true);
    defer allocator.free(slots);

    // In SoftHSM, you init new tokens using the last slot.
    const slot = slots[slots.len - 1];

    try mod.initToken(slot, "1234", "zig-p11");

    var sess = try mod.openSession(slot, .{});
    defer sess.deinit();

    try sess.login(UserType.system_operator, "1234");
    try sess.initPIN("4321");
}

test "it can open and close a session" {
    const allocator = testing.allocator;
    var mod = try Module.init(allocator, config.module);
    defer mod.deinit();
    try mod.initialize();
    defer mod.finalize() catch {};

    const slots = try mod.getSlotList(true);
    defer allocator.free(slots);

    const slot = slots[1];
    var sess = try mod.openSession(slot, .{});
    defer sess.deinit();
    try sess.close();

    var sess2 = try mod.openSession(slot, .{});
    defer sess2.deinit();
    try mod.closeAllSessions(slot);
}
