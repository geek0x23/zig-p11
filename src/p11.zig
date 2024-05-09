const std = @import("std");
const builtin = @import("builtin");
const config = @import("config");
const C = @cImport({
    @cInclude("cryptoki.h");
});

const Allocator = std.mem.Allocator;
const testing = std.testing;

pub const Version = struct {
    major: u8,
    minor: u8,

    fn fromCType(version: C.CK_VERSION) Version {
        return .{ .major = version.major, .minor = version.minor };
    }
};

pub const SlotInfo = struct {
    description: [64]u8,
    manufacturer_id: [32]u8,
    flags: SlotFlags,
    hardware_version: Version,
    firmware_version: Version,

    fn fromCType(info: C.CK_SLOT_INFO) SlotInfo {
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

    fn fromCType(flags: C.CK_FLAGS) SlotFlags {
        return .{
            .hardware_slot = (flags & C.CKF_HW_SLOT) == flags,
            .removable_device = (flags & C.CKF_REMOVABLE_DEVICE) == flags,
            .token_present = (flags & C.CKF_TOKEN_PRESENT) == flags,
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

    fn fromCType(info: C.CK_INFO) Info {
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
    max_session_count: u64,
    session_count: u64,
    max_rw_session_count: u64,
    rw_session_count: u64,
    max_pin_len: u64,
    min_pin_len: u64,
    total_public_memory: u64,
    free_public_memory: u64,
    total_private_memory: u64,
    free_private_memory: u64,
    hardware_version: Version,
    firmware_version: Version,
    utc_time: [16]u8,

    fn fromCType(info: C.CK_TOKEN_INFO) TokenInfo {
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

    fn fromCType(flags: C.CK_FLAGS) TokenFlags {
        return .{
            .rng = (flags & C.CKF_RNG) == flags,
            .write_protected = (flags & C.CKF_WRITE_PROTECTED) == flags,
            .login_required = (flags & C.CKF_LOGIN_REQUIRED) == flags,
            .user_pin_initialized = (flags & C.CKF_USER_PIN_INITIALIZED) == flags,
            .restore_key_not_needed = (flags & C.CKF_RESTORE_KEY_NOT_NEEDED) == flags,
            .clock_on_token = (flags & C.CKF_CLOCK_ON_TOKEN) == flags,
            .protected_authentication_path = (flags & C.CKF_PROTECTED_AUTHENTICATION_PATH) == flags,
            .dual_crypto_operations = (flags & C.CKF_DUAL_CRYPTO_OPERATIONS) == flags,
            .token_initialized = (flags & C.CKF_TOKEN_INITIALIZED) == flags,
            .secondary_authentication = (flags & C.CKF_SECONDARY_AUTHENTICATION) == flags,
            .user_pin_count_low = (flags & C.CKF_USER_PIN_COUNT_LOW) == flags,
            .user_pin_final_try = (flags & C.CKF_USER_PIN_FINAL_TRY) == flags,
            .user_pin_locked = (flags & C.CKF_USER_PIN_LOCKED) == flags,
            .user_pin_to_be_changed = (flags & C.CKF_USER_PIN_TO_BE_CHANGED) == flags,
            .so_pin_count_low = (flags & C.CKF_SO_PIN_COUNT_LOW) == flags,
            .so_pin_final_try = (flags & C.CKF_SO_PIN_FINAL_TRY) == flags,
            .so_pin_locked = (flags & C.CKF_SO_PIN_LOCKED) == flags,
            .so_pin_to_be_changed = (flags & C.CKF_SO_PIN_TO_BE_CHANGED) == flags,
            .error_state = (flags & C.CKF_ERROR_STATE) == flags,
        };
    }
};

pub const UserType = enum(u64) {
    SystemOperator = C.CKU_SO,
    User = C.CKU_USER,
    ContextSpecific = C.CKU_CONTEXT_SPECIFIC,
};

const Context = struct {
    lib: std.DynLib,
    sym: *C.CK_FUNCTION_LIST,
};

pub const PKCS11Token = struct {
    ctx: *Context,
    allocator: Allocator,

    /// Caller must deinit() to close the library and free memory.
    /// Opens the given PKCS#11 library and loads symbols from it.
    pub fn init(alloc: Allocator, path: []const u8) !PKCS11Token {
        var lib = try std.DynLib.open(path);

        const context = try alloc.create(Context);
        context.lib = lib;

        const getFunctionList = lib.lookup(C.CK_C_GetFunctionList, "C_GetFunctionList").?.?;
        const rv = getFunctionList(@ptrCast(&context.sym));
        try returnIfError(rv);

        return .{ .allocator = alloc, .ctx = context };
    }

    /// Closes the PKCS#11 library and frees memory.
    pub fn deinit(self: *PKCS11Token) void {
        self.ctx.lib.close();
        self.allocator.destroy(self.ctx);
        self.* = undefined;
    }

    /// Initializes the PKCS#11 module.
    pub fn initialize(self: PKCS11Token) Error!void {
        var args: C.CK_C_INITIALIZE_ARGS = .{ .flags = C.CKF_OS_LOCKING_OK };
        const rv = self.ctx.sym.C_Initialize.?(&args);
        try returnIfError(rv);
    }

    /// Finalizes the PKCS#11 module.
    pub fn finalize(self: PKCS11Token) Error!void {
        const args: C.CK_VOID_PTR = null;
        const rv = self.ctx.sym.C_Finalize.?(args);
        try returnIfError(rv);
    }

    /// Caller must free returned memory
    /// Retrieves general token information.
    pub fn getInfo(self: PKCS11Token) Error!Info {
        var info: C.CK_INFO = undefined;
        const rv = self.ctx.sym.C_GetInfo.?(&info);
        try returnIfError(rv);

        return Info.fromCType(info);
    }

    /// Caller owns returned memory.
    /// Retrieves a slot list.
    pub fn getSlotList(self: PKCS11Token, token_present: bool) Error![]u64 {
        const present: C.CK_BBOOL = if (token_present) C.CK_TRUE else C.CK_FALSE;
        var slot_count: C.CK_ULONG = undefined;

        var rv = self.ctx.sym.C_GetSlotList.?(present, null, &slot_count);
        try returnIfError(rv);

        const slot_list = try self.allocator.alloc(C.CK_ULONG, slot_count);
        rv = self.ctx.sym.C_GetSlotList.?(present, slot_list.ptr, &slot_count);
        try returnIfError(rv);

        return slot_list;
    }

    /// Retrieves information about the given slot.
    pub fn getSlotInfo(self: PKCS11Token, slot_id: u64) Error!SlotInfo {
        var slot_info: C.CK_SLOT_INFO = undefined;
        const rv = self.ctx.sym.C_GetSlotInfo.?(slot_id, &slot_info);
        try returnIfError(rv);

        return SlotInfo.fromCType(slot_info);
    }

    /// Retrieves information about the token in the given slot.
    pub fn getTokenInfo(self: PKCS11Token, slot_id: u64) Error!TokenInfo {
        var token_info: C.CK_TOKEN_INFO = undefined;
        const rv = self.ctx.sym.C_GetTokenInfo.?(slot_id, &token_info);
        try returnIfError(rv);

        return TokenInfo.fromCType(token_info);
    }
};

pub const Error = error{
    // PKCS#11 Errors
    Cancel,
    HostMemory,
    SlotIdInvalid,
    GeneralError,
    FunctionFailed,
    ArgumentsBad,
    NoEvent,
    NeedToCreateThreads,
    CantLock,
    AttributeReadOnly,
    AttributeSensitive,
    AttributeTypeInvalid,
    AttributeValueInvalid,
    ActionProhibited,
    DataInvalid,
    DataLenRange,
    DeviceError,
    DeviceMemory,
    DeviceRemoved,
    EncryptedDataInvalid,
    EncryptedDataLenRange,
    FunctionCancelled,
    FunctionNotParallel,
    FunctionNotSupported,
    KeyHandleInvalid,
    KeySizeRange,
    KeyTypeInconsistent,
    KeyNotNeeded,
    KeyChanged,
    KeyNeeded,
    KeyIndigestible,
    KeyFunctionNotPermitted,
    KeyNotWrappable,
    KeyUnextractable,
    MechanismInvalid,
    MechanismParamInvalid,
    ObjectHandleInvalid,
    OperationActive,
    OperationNotInitialized,
    PINIncorrect,
    PINInvalid,
    PINLenRange,
    PINExpired,
    PINLocked,
    SessionClosed,
    SessionCount,
    SessionHandleInvalid,
    SessionParallelNotSupported,
    SessionReadOnly,
    SessionExists,
    SessionReadOnlyExists,
    SessionReadWriteSOExists,
    SignatureInvalid,
    SignatureLenRange,
    TemplateIncomplete,
    TemplateInconsistent,
    TokenNotPresent,
    TokenNotRecognized,
    TokenWriteProhibited,
    UnwrappingKeyHandleInvalid,
    UnwrappingKeySizeRange,
    UnwrappingKeyTypeInconsistent,
    UserAlreadyLoggedIn,
    UserNotLoggedIn,
    UserPINNotInitialized,
    UserTypeInvalid,
    UserAnotherAlreadyLoggedIn,
    UserTooManyTypes,
    WrappedKeyInvalid,
    WrappedKeyLenRange,
    WrappingKeyHandleInvalid,
    WrappingKeySizeRange,
    WrappingKeyTypeInconsistent,
    RandomSeedNotSupported,
    RandomNoRNG,
    DomainParamsInvalid,
    CurveNotSupported,
    BufferTooSmall,
    SavedStateInvalid,
    InformationSensitive,
    StateUnsavable,
    CryptokiNotInitialized,
    CryptokiAlreadyInitialized,
    MutexBad,
    MutexNotLocked,
    NewPINMode,
    NextOTP,
    ExceededMaxIterations,
    FIPSSelfTestFailed,
    LibraryLoadFailed,
    PINTooWeak,
    PublicKeyInvalid,
    FunctionRejected,
    // Our own errors
    Unknown,
    OutOfMemory,
};

fn returnValueToError(rv: ReturnValue) Error {
    return switch (rv) {
        .CANCEL => Error.Cancel,
        .HOST_MEMORY => Error.HostMemory,
        .SLOT_ID_INVALID => Error.SlotIdInvalid,
        .GENERAL_ERROR => Error.GeneralError,
        .FUNCTION_FAILED => Error.FunctionFailed,
        .ARGUMENTS_BAD => Error.ArgumentsBad,
        .NO_EVENT => Error.NoEvent,
        .NEED_TO_CREATE_THREADS => Error.NeedToCreateThreads,
        .CANT_LOCK => Error.CantLock,
        .ATTRIBUTE_READ_ONLY => Error.AttributeReadOnly,
        .ATTRIBUTE_SENSITIVE => Error.AttributeSensitive,
        .ATTRIBUTE_TYPE_INVALID => Error.AttributeTypeInvalid,
        .ATTRIBUTE_VALUE_INVALID => Error.AttributeValueInvalid,
        .ACTION_PROHIBITED => Error.ActionProhibited,
        .DATA_INVALID => Error.DataInvalid,
        .DATA_LEN_RANGE => Error.DataLenRange,
        .DEVICE_ERROR => Error.DeviceError,
        .DEVICE_MEMORY => Error.DeviceMemory,
        .DEVICE_REMOVED => Error.DeviceRemoved,
        .ENCRYPTED_DATA_INVALID => Error.EncryptedDataInvalid,
        .ENCRYPTED_DATA_LEN_RANGE => Error.EncryptedDataLenRange,
        .FUNCTION_CANCELED => Error.FunctionCancelled,
        .FUNCTION_NOT_PARALLEL => Error.FunctionNotParallel,
        .FUNCTION_NOT_SUPPORTED => Error.FunctionNotSupported,
        .KEY_HANDLE_INVALID => Error.KeyHandleInvalid,
        .KEY_SIZE_RANGE => Error.KeySizeRange,
        .KEY_TYPE_INCONSISTENT => Error.KeyTypeInconsistent,
        .KEY_NOT_NEEDED => Error.KeyNotNeeded,
        .KEY_CHANGED => Error.KeyChanged,
        .KEY_NEEDED => Error.KeyNeeded,
        .KEY_INDIGESTIBLE => Error.KeyIndigestible,
        .KEY_FUNCTION_NOT_PERMITTED => Error.KeyFunctionNotPermitted,
        .KEY_NOT_WRAPPABLE => Error.KeyNotWrappable,
        .KEY_UNEXTRACTABLE => Error.KeyUnextractable,
        .MECHANISM_INVALID => Error.MechanismInvalid,
        .MECHANISM_PARAM_INVALID => Error.MechanismParamInvalid,
        .OBJECT_HANDLE_INVALID => Error.ObjectHandleInvalid,
        .OPERATION_ACTIVE => Error.OperationActive,
        .OPERATION_NOT_INITIALIZED => Error.OperationNotInitialized,
        .PIN_INCORRECT => Error.PINIncorrect,
        .PIN_INVALID => Error.PINInvalid,
        .PIN_LEN_RANGE => Error.PINLenRange,
        .PIN_EXPIRED => Error.PINExpired,
        .PIN_LOCKED => Error.PINLocked,
        .SESSION_CLOSED => Error.SessionClosed,
        .SESSION_COUNT => Error.SessionCount,
        .SESSION_HANDLE_INVALID => Error.SessionHandleInvalid,
        .SESSION_PARALLEL_NOT_SUPPORTED => Error.SessionParallelNotSupported,
        .SESSION_READ_ONLY => Error.SessionReadOnly,
        .SESSION_EXISTS => Error.SessionExists,
        .SESSION_READ_ONLY_EXISTS => Error.SessionReadOnlyExists,
        .SESSION_READ_WRITE_SO_EXISTS => Error.SessionReadWriteSOExists,
        .SIGNATURE_INVALID => Error.SignatureInvalid,
        .SIGNATURE_LEN_RANGE => Error.SignatureLenRange,
        .TEMPLATE_INCOMPLETE => Error.TemplateIncomplete,
        .TEMPLATE_INCONSISTENT => Error.TemplateInconsistent,
        .TOKEN_NOT_PRESENT => Error.TokenNotPresent,
        .TOKEN_NOT_RECOGNIZED => Error.TokenNotRecognized,
        .TOKEN_WRITE_PROTECTED => Error.TokenWriteProhibited,
        .UNWRAPPING_KEY_HANDLE_INVALID => Error.UnwrappingKeyHandleInvalid,
        .UNWRAPPING_KEY_SIZE_RANGE => Error.UnwrappingKeySizeRange,
        .UNWRAPPING_KEY_TYPE_INCONSISTENT => Error.UnwrappingKeyTypeInconsistent,
        .USER_ALREADY_LOGGED_IN => Error.UserAlreadyLoggedIn,
        .USER_NOT_LOGGED_IN => Error.UserNotLoggedIn,
        .USER_PIN_NOT_INITIALIZED => Error.UserPINNotInitialized,
        .USER_TYPE_INVALID => Error.UserTypeInvalid,
        .USER_ANOTHER_ALREADY_LOGGED_IN => Error.UserAnotherAlreadyLoggedIn,
        .USER_TOO_MANY_TYPES => Error.UserTooManyTypes,
        .WRAPPED_KEY_INVALID => Error.WrappedKeyInvalid,
        .WRAPPED_KEY_LEN_RANGE => Error.WrappedKeyLenRange,
        .WRAPPING_KEY_HANDLE_INVALID => Error.WrappingKeyHandleInvalid,
        .WRAPPING_KEY_SIZE_RANGE => Error.WrappingKeySizeRange,
        .WRAPPING_KEY_TYPE_INCONSISTENT => Error.WrappingKeyTypeInconsistent,
        .RANDOM_SEED_NOT_SUPPORTED => Error.RandomSeedNotSupported,
        .RANDOM_NO_RNG => Error.RandomNoRNG,
        .DOMAIN_PARAMS_INVALID => Error.DomainParamsInvalid,
        .CURVE_NOT_SUPPORTED => Error.CurveNotSupported,
        .BUFFER_TOO_SMALL => Error.BufferTooSmall,
        .SAVED_STATE_INVALID => Error.SavedStateInvalid,
        .INFORMATION_SENSITIVE => Error.InformationSensitive,
        .STATE_UNSAVEABLE => Error.StateUnsavable,
        .CRYPTOKI_NOT_INITIALIZED => Error.CryptokiNotInitialized,
        .CRYPTOKI_ALREADY_INITIALIZED => Error.CryptokiAlreadyInitialized,
        .MUTEX_BAD => Error.MutexBad,
        .MUTEX_NOT_LOCKED => Error.MutexNotLocked,
        .NEW_PIN_MODE => Error.NewPINMode,
        .NEXT_OTP => Error.NextOTP,
        .EXCEEDED_MAX_ITERATIONS => Error.ExceededMaxIterations,
        .FIPS_SELF_TEST_FAILED => Error.FIPSSelfTestFailed,
        .LIBRARY_LOAD_FAILED => Error.LibraryLoadFailed,
        .PIN_TOO_WEAK => Error.PINTooWeak,
        .PUBLIC_KEY_INVALID => Error.PublicKeyInvalid,
        .FUNCTION_REJECTED => Error.FunctionRejected,
        else => Error.Unknown,
    };
}

const ReturnValue = enum(c_ulong) {
    OK = C.CKR_OK,
    CANCEL = C.CKR_CANCEL,
    HOST_MEMORY = C.CKR_HOST_MEMORY,
    SLOT_ID_INVALID = C.CKR_SLOT_ID_INVALID,
    GENERAL_ERROR = C.CKR_GENERAL_ERROR,
    FUNCTION_FAILED = C.CKR_FUNCTION_FAILED,
    ARGUMENTS_BAD = C.CKR_ARGUMENTS_BAD,
    NO_EVENT = C.CKR_NO_EVENT,
    NEED_TO_CREATE_THREADS = C.CKR_NEED_TO_CREATE_THREADS,
    CANT_LOCK = C.CKR_CANT_LOCK,
    ATTRIBUTE_READ_ONLY = C.CKR_ATTRIBUTE_READ_ONLY,
    ATTRIBUTE_SENSITIVE = C.CKR_ATTRIBUTE_SENSITIVE,
    ATTRIBUTE_TYPE_INVALID = C.CKR_ATTRIBUTE_TYPE_INVALID,
    ATTRIBUTE_VALUE_INVALID = C.CKR_ATTRIBUTE_VALUE_INVALID,
    ACTION_PROHIBITED = C.CKR_ACTION_PROHIBITED,
    DATA_INVALID = C.CKR_DATA_INVALID,
    DATA_LEN_RANGE = C.CKR_DATA_LEN_RANGE,
    DEVICE_ERROR = C.CKR_DEVICE_ERROR,
    DEVICE_MEMORY = C.CKR_DEVICE_MEMORY,
    DEVICE_REMOVED = C.CKR_DEVICE_REMOVED,
    ENCRYPTED_DATA_INVALID = C.CKR_ENCRYPTED_DATA_INVALID,
    ENCRYPTED_DATA_LEN_RANGE = C.CKR_ENCRYPTED_DATA_LEN_RANGE,
    FUNCTION_CANCELED = C.CKR_FUNCTION_CANCELED,
    FUNCTION_NOT_PARALLEL = C.CKR_FUNCTION_NOT_PARALLEL,
    FUNCTION_NOT_SUPPORTED = C.CKR_FUNCTION_NOT_SUPPORTED,
    KEY_HANDLE_INVALID = C.CKR_KEY_HANDLE_INVALID,
    KEY_SIZE_RANGE = C.CKR_KEY_SIZE_RANGE,
    KEY_TYPE_INCONSISTENT = C.CKR_KEY_TYPE_INCONSISTENT,
    KEY_NOT_NEEDED = C.CKR_KEY_NOT_NEEDED,
    KEY_CHANGED = C.CKR_KEY_CHANGED,
    KEY_NEEDED = C.CKR_KEY_NEEDED,
    KEY_INDIGESTIBLE = C.CKR_KEY_INDIGESTIBLE,
    KEY_FUNCTION_NOT_PERMITTED = C.CKR_KEY_FUNCTION_NOT_PERMITTED,
    KEY_NOT_WRAPPABLE = C.CKR_KEY_NOT_WRAPPABLE,
    KEY_UNEXTRACTABLE = C.CKR_KEY_UNEXTRACTABLE,
    MECHANISM_INVALID = C.CKR_MECHANISM_INVALID,
    MECHANISM_PARAM_INVALID = C.CKR_MECHANISM_PARAM_INVALID,
    OBJECT_HANDLE_INVALID = C.CKR_OBJECT_HANDLE_INVALID,
    OPERATION_ACTIVE = C.CKR_OPERATION_ACTIVE,
    OPERATION_NOT_INITIALIZED = C.CKR_OPERATION_NOT_INITIALIZED,
    PIN_INCORRECT = C.CKR_PIN_INCORRECT,
    PIN_INVALID = C.CKR_PIN_INVALID,
    PIN_LEN_RANGE = C.CKR_PIN_LEN_RANGE,
    PIN_EXPIRED = C.CKR_PIN_EXPIRED,
    PIN_LOCKED = C.CKR_PIN_LOCKED,
    SESSION_CLOSED = C.CKR_SESSION_CLOSED,
    SESSION_COUNT = C.CKR_SESSION_COUNT,
    SESSION_HANDLE_INVALID = C.CKR_SESSION_HANDLE_INVALID,
    SESSION_PARALLEL_NOT_SUPPORTED = C.CKR_SESSION_PARALLEL_NOT_SUPPORTED,
    SESSION_READ_ONLY = C.CKR_SESSION_READ_ONLY,
    SESSION_EXISTS = C.CKR_SESSION_EXISTS,
    SESSION_READ_ONLY_EXISTS = C.CKR_SESSION_READ_ONLY_EXISTS,
    SESSION_READ_WRITE_SO_EXISTS = C.CKR_SESSION_READ_WRITE_SO_EXISTS,
    SIGNATURE_INVALID = C.CKR_SIGNATURE_INVALID,
    SIGNATURE_LEN_RANGE = C.CKR_SIGNATURE_LEN_RANGE,
    TEMPLATE_INCOMPLETE = C.CKR_TEMPLATE_INCOMPLETE,
    TEMPLATE_INCONSISTENT = C.CKR_TEMPLATE_INCONSISTENT,
    TOKEN_NOT_PRESENT = C.CKR_TOKEN_NOT_PRESENT,
    TOKEN_NOT_RECOGNIZED = C.CKR_TOKEN_NOT_RECOGNIZED,
    TOKEN_WRITE_PROTECTED = C.CKR_TOKEN_WRITE_PROTECTED,
    UNWRAPPING_KEY_HANDLE_INVALID = C.CKR_UNWRAPPING_KEY_HANDLE_INVALID,
    UNWRAPPING_KEY_SIZE_RANGE = C.CKR_UNWRAPPING_KEY_SIZE_RANGE,
    UNWRAPPING_KEY_TYPE_INCONSISTENT = C.CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT,
    USER_ALREADY_LOGGED_IN = C.CKR_USER_ALREADY_LOGGED_IN,
    USER_NOT_LOGGED_IN = C.CKR_USER_NOT_LOGGED_IN,
    USER_PIN_NOT_INITIALIZED = C.CKR_USER_PIN_NOT_INITIALIZED,
    USER_TYPE_INVALID = C.CKR_USER_TYPE_INVALID,
    USER_ANOTHER_ALREADY_LOGGED_IN = C.CKR_USER_ANOTHER_ALREADY_LOGGED_IN,
    USER_TOO_MANY_TYPES = C.CKR_USER_TOO_MANY_TYPES,
    WRAPPED_KEY_INVALID = C.CKR_WRAPPED_KEY_INVALID,
    WRAPPED_KEY_LEN_RANGE = C.CKR_WRAPPED_KEY_LEN_RANGE,
    WRAPPING_KEY_HANDLE_INVALID = C.CKR_WRAPPING_KEY_HANDLE_INVALID,
    WRAPPING_KEY_SIZE_RANGE = C.CKR_WRAPPING_KEY_SIZE_RANGE,
    WRAPPING_KEY_TYPE_INCONSISTENT = C.CKR_WRAPPING_KEY_TYPE_INCONSISTENT,
    RANDOM_SEED_NOT_SUPPORTED = C.CKR_RANDOM_SEED_NOT_SUPPORTED,
    RANDOM_NO_RNG = C.CKR_RANDOM_NO_RNG,
    DOMAIN_PARAMS_INVALID = C.CKR_DOMAIN_PARAMS_INVALID,
    CURVE_NOT_SUPPORTED = C.CKR_CURVE_NOT_SUPPORTED,
    BUFFER_TOO_SMALL = C.CKR_BUFFER_TOO_SMALL,
    SAVED_STATE_INVALID = C.CKR_SAVED_STATE_INVALID,
    INFORMATION_SENSITIVE = C.CKR_INFORMATION_SENSITIVE,
    STATE_UNSAVEABLE = C.CKR_STATE_UNSAVEABLE,
    CRYPTOKI_NOT_INITIALIZED = C.CKR_CRYPTOKI_NOT_INITIALIZED,
    CRYPTOKI_ALREADY_INITIALIZED = C.CKR_CRYPTOKI_ALREADY_INITIALIZED,
    MUTEX_BAD = C.CKR_MUTEX_BAD,
    MUTEX_NOT_LOCKED = C.CKR_MUTEX_NOT_LOCKED,
    NEW_PIN_MODE = C.CKR_NEW_PIN_MODE,
    NEXT_OTP = C.CKR_NEXT_OTP,
    EXCEEDED_MAX_ITERATIONS = C.CKR_EXCEEDED_MAX_ITERATIONS,
    FIPS_SELF_TEST_FAILED = C.CKR_FIPS_SELF_TEST_FAILED,
    LIBRARY_LOAD_FAILED = C.CKR_LIBRARY_LOAD_FAILED,
    PIN_TOO_WEAK = C.CKR_PIN_TOO_WEAK,
    PUBLIC_KEY_INVALID = C.CKR_PUBLIC_KEY_INVALID,
    FUNCTION_REJECTED = C.CKR_FUNCTION_REJECTED,
    VENDOR_DEFINED = C.CKR_VENDOR_DEFINED,
};

fn returnIfError(rv: c_ulong) Error!void {
    const result: ReturnValue = @enumFromInt(rv);
    if (result != ReturnValue.OK) {
        return returnValueToError(result);
    }
}

test "it can load a PKCS#11 library." {
    var token = try PKCS11Token.init(testing.allocator, config.module);
    defer token.deinit();
}

test "it can initialize and finalize the token." {
    var token = try PKCS11Token.init(testing.allocator, config.module);
    defer token.deinit();

    try token.initialize();
    try token.finalize();
}

test "it can get all the infos" {
    const allocator = testing.allocator;
    var token = try PKCS11Token.init(allocator, config.module);

    defer token.deinit();
    try token.initialize();

    const slots = try token.getSlotList(false);
    defer allocator.free(slots);
    try testing.expect(slots.len > 0);

    const slot_info = try token.getSlotInfo(slots[0]);
    try testing.expectStringStartsWith(&slot_info.description, "SoftHSM");

    const info = try token.getInfo();
    try testing.expectStringStartsWith(&info.manufacturer_id, "SoftHSM");

    const token_info = try token.getTokenInfo(slots[0]);
    try testing.expectStringStartsWith(&token_info.manufacturer_id, "SoftHSM");
}
