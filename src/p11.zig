const std = @import("std");
const log = std.log.scoped(.p11);
const builtin = @import("builtin");
const config = @import("config");
const C = @cImport({
    @cInclude("cryptoki.h");
});

const Allocator = std.mem.Allocator;
const mem = std.mem;
const testing = std.testing;

pub const Version = struct {
    major: u8,
    minor: u8,
};

pub const SlotInfo = struct {
    description: [64]u8,
    manufacturer_id: [32]u8,
    flags: SlotFlags,
    hardware_version: Version,
    firmware_version: Version,
};

pub const SlotFlags = struct {
    token_present: bool = false,
    removable_device: bool = false,
    hardware_slot: bool = false,
};

pub const Info = struct {
    cryptoki_version: Version,
    manufacturer_id: [32]u8,
    flags: u8 = 0, // per PKCS#11 spec, this field is always zero.
    library_description: [32]u8,
    library_version: Version,
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
        var c_info: C.CK_INFO = undefined;
        const rv = self.ctx.sym.C_GetInfo.?(&c_info);
        try returnIfError(rv);

        return .{
            .manufacturer_id = c_info.manufacturerID,
            .library_description = c_info.libraryDescription,
            // flags omitted intentionally.
            .cryptoki_version = .{
                .major = c_info.cryptokiVersion.major,
                .minor = c_info.cryptokiVersion.minor,
            },
            .library_version = .{
                .major = c_info.libraryVersion.major,
                .minor = c_info.libraryVersion.minor,
            },
        };
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
        var c_slot_info: C.CK_SLOT_INFO = undefined;
        const rv = self.ctx.sym.C_GetSlotInfo.?(slot_id, &c_slot_info);
        try returnIfError(rv);

        return .{
            .description = c_slot_info.slotDescription,
            .manufacturer_id = c_slot_info.manufacturerID,
            .flags = .{
                .hardware_slot = (c_slot_info.flags & C.CKF_HW_SLOT) == c_slot_info.flags,
                .removable_device = (c_slot_info.flags & C.CKF_REMOVABLE_DEVICE) == c_slot_info.flags,
                .token_present = (c_slot_info.flags & C.CKF_TOKEN_PRESENT) == c_slot_info.flags,
            },
            .hardware_version = .{
                .major = c_slot_info.hardwareVersion.major,
                .minor = c_slot_info.hardwareVersion.minor,
            },
            .firmware_version = .{
                .major = c_slot_info.firmwareVersion.major,
                .minor = c_slot_info.firmwareVersion.minor,
            },
        };
    }

    /// Retrieves information about the token in the given slot.
    pub fn getTokenInfo(self: PKCS11Token, slot_id: u64) Error!TokenInfo {
        var c_token_info: C.CK_TOKEN_INFO = undefined;
        const rv = self.ctx.sym.C_GetTokenInfo.?(slot_id, &c_token_info);
        try returnIfError(rv);

        return .{
            .label = c_token_info.label,
            .manufacturer_id = c_token_info.manufacturerID,
            .model = c_token_info.model,
            .serial_number = c_token_info.serialNumber,
            .flags = .{
                .rng = (c_token_info.flags & C.CKF_RNG) == c_token_info.flags,
                .write_protected = (c_token_info.flags & C.CKF_WRITE_PROTECTED) == c_token_info.flags,
                .login_required = (c_token_info.flags & C.CKF_LOGIN_REQUIRED) == c_token_info.flags,
                .user_pin_initialized = (c_token_info.flags & C.CKF_USER_PIN_INITIALIZED) == c_token_info.flags,
                .restore_key_not_needed = (c_token_info.flags & C.CKF_RESTORE_KEY_NOT_NEEDED) == c_token_info.flags,
                .clock_on_token = (c_token_info.flags & C.CKF_CLOCK_ON_TOKEN) == c_token_info.flags,
                .protected_authentication_path = (c_token_info.flags & C.CKF_PROTECTED_AUTHENTICATION_PATH) == c_token_info.flags,
                .dual_crypto_operations = (c_token_info.flags & C.CKF_DUAL_CRYPTO_OPERATIONS) == c_token_info.flags,
                .token_initialized = (c_token_info.flags & C.CKF_TOKEN_INITIALIZED) == c_token_info.flags,
                .secondary_authentication = (c_token_info.flags & C.CKF_SECONDARY_AUTHENTICATION) == c_token_info.flags,
                .user_pin_count_low = (c_token_info.flags & C.CKF_USER_PIN_COUNT_LOW) == c_token_info.flags,
                .user_pin_final_try = (c_token_info.flags & C.CKF_USER_PIN_FINAL_TRY) == c_token_info.flags,
                .user_pin_locked = (c_token_info.flags & C.CKF_USER_PIN_LOCKED) == c_token_info.flags,
                .user_pin_to_be_changed = (c_token_info.flags & C.CKF_USER_PIN_TO_BE_CHANGED) == c_token_info.flags,
                .so_pin_count_low = (c_token_info.flags & C.CKF_SO_PIN_COUNT_LOW) == c_token_info.flags,
                .so_pin_final_try = (c_token_info.flags & C.CKF_SO_PIN_FINAL_TRY) == c_token_info.flags,
                .so_pin_locked = (c_token_info.flags & C.CKF_SO_PIN_LOCKED) == c_token_info.flags,
                .so_pin_to_be_changed = (c_token_info.flags & C.CKF_SO_PIN_TO_BE_CHANGED) == c_token_info.flags,
                .error_state = (c_token_info.flags & C.CKF_ERROR_STATE) == c_token_info.flags,
            },
            .max_session_count = c_token_info.ulMaxSessionCount,
            .session_count = c_token_info.ulSessionCount,
            .max_rw_session_count = c_token_info.ulMaxRwSessionCount,
            .rw_session_count = c_token_info.ulRwSessionCount,
            .max_pin_len = c_token_info.ulMaxPinLen,
            .min_pin_len = c_token_info.ulMinPinLen,
            .total_public_memory = c_token_info.ulTotalPublicMemory,
            .free_public_memory = c_token_info.ulFreePublicMemory,
            .total_private_memory = c_token_info.ulTotalPrivateMemory,
            .free_private_memory = c_token_info.ulFreePrivateMemory,
            .hardware_version = .{
                .major = c_token_info.hardwareVersion.major,
                .minor = c_token_info.hardwareVersion.minor,
            },
            .firmware_version = .{
                .major = c_token_info.firmwareVersion.major,
                .minor = c_token_info.firmwareVersion.minor,
            },
            .utc_time = c_token_info.utcTime,
        };
    }

    pub const Error = error{
        // PKCS#11 Token Errors
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
};

fn returnValueToError(rv: ReturnValue) PKCS11Token.Error {
    return switch (rv) {
        .CANCEL => PKCS11Token.Error.Cancel,
        .HOST_MEMORY => PKCS11Token.Error.HostMemory,
        .SLOT_ID_INVALID => PKCS11Token.Error.SlotIdInvalid,
        .GENERAL_ERROR => PKCS11Token.Error.GeneralError,
        .FUNCTION_FAILED => PKCS11Token.Error.FunctionFailed,
        .ARGUMENTS_BAD => PKCS11Token.Error.ArgumentsBad,
        .NO_EVENT => PKCS11Token.Error.NoEvent,
        .NEED_TO_CREATE_THREADS => PKCS11Token.Error.NeedToCreateThreads,
        .CANT_LOCK => PKCS11Token.Error.CantLock,
        .ATTRIBUTE_READ_ONLY => PKCS11Token.Error.AttributeReadOnly,
        .ATTRIBUTE_SENSITIVE => PKCS11Token.Error.AttributeSensitive,
        .ATTRIBUTE_TYPE_INVALID => PKCS11Token.Error.AttributeTypeInvalid,
        .ATTRIBUTE_VALUE_INVALID => PKCS11Token.Error.AttributeValueInvalid,
        .ACTION_PROHIBITED => PKCS11Token.Error.ActionProhibited,
        .DATA_INVALID => PKCS11Token.Error.DataInvalid,
        .DATA_LEN_RANGE => PKCS11Token.Error.DataLenRange,
        .DEVICE_ERROR => PKCS11Token.Error.DeviceError,
        .DEVICE_MEMORY => PKCS11Token.Error.DeviceMemory,
        .DEVICE_REMOVED => PKCS11Token.Error.DeviceRemoved,
        .ENCRYPTED_DATA_INVALID => PKCS11Token.Error.EncryptedDataInvalid,
        .ENCRYPTED_DATA_LEN_RANGE => PKCS11Token.Error.EncryptedDataLenRange,
        .FUNCTION_CANCELED => PKCS11Token.Error.FunctionCancelled,
        .FUNCTION_NOT_PARALLEL => PKCS11Token.Error.FunctionNotParallel,
        .FUNCTION_NOT_SUPPORTED => PKCS11Token.Error.FunctionNotSupported,
        .KEY_HANDLE_INVALID => PKCS11Token.Error.KeyHandleInvalid,
        .KEY_SIZE_RANGE => PKCS11Token.Error.KeySizeRange,
        .KEY_TYPE_INCONSISTENT => PKCS11Token.Error.KeyTypeInconsistent,
        .KEY_NOT_NEEDED => PKCS11Token.Error.KeyNotNeeded,
        .KEY_CHANGED => PKCS11Token.Error.KeyChanged,
        .KEY_NEEDED => PKCS11Token.Error.KeyNeeded,
        .KEY_INDIGESTIBLE => PKCS11Token.Error.KeyIndigestible,
        .KEY_FUNCTION_NOT_PERMITTED => PKCS11Token.Error.KeyFunctionNotPermitted,
        .KEY_NOT_WRAPPABLE => PKCS11Token.Error.KeyNotWrappable,
        .KEY_UNEXTRACTABLE => PKCS11Token.Error.KeyUnextractable,
        .MECHANISM_INVALID => PKCS11Token.Error.MechanismInvalid,
        .MECHANISM_PARAM_INVALID => PKCS11Token.Error.MechanismParamInvalid,
        .OBJECT_HANDLE_INVALID => PKCS11Token.Error.ObjectHandleInvalid,
        .OPERATION_ACTIVE => PKCS11Token.Error.OperationActive,
        .OPERATION_NOT_INITIALIZED => PKCS11Token.Error.OperationNotInitialized,
        .PIN_INCORRECT => PKCS11Token.Error.PINIncorrect,
        .PIN_INVALID => PKCS11Token.Error.PINInvalid,
        .PIN_LEN_RANGE => PKCS11Token.Error.PINLenRange,
        .PIN_EXPIRED => PKCS11Token.Error.PINExpired,
        .PIN_LOCKED => PKCS11Token.Error.PINLocked,
        .SESSION_CLOSED => PKCS11Token.Error.SessionClosed,
        .SESSION_COUNT => PKCS11Token.Error.SessionCount,
        .SESSION_HANDLE_INVALID => PKCS11Token.Error.SessionHandleInvalid,
        .SESSION_PARALLEL_NOT_SUPPORTED => PKCS11Token.Error.SessionParallelNotSupported,
        .SESSION_READ_ONLY => PKCS11Token.Error.SessionReadOnly,
        .SESSION_EXISTS => PKCS11Token.Error.SessionExists,
        .SESSION_READ_ONLY_EXISTS => PKCS11Token.Error.SessionReadOnlyExists,
        .SESSION_READ_WRITE_SO_EXISTS => PKCS11Token.Error.SessionReadWriteSOExists,
        .SIGNATURE_INVALID => PKCS11Token.Error.SignatureInvalid,
        .SIGNATURE_LEN_RANGE => PKCS11Token.Error.SignatureLenRange,
        .TEMPLATE_INCOMPLETE => PKCS11Token.Error.TemplateIncomplete,
        .TEMPLATE_INCONSISTENT => PKCS11Token.Error.TemplateInconsistent,
        .TOKEN_NOT_PRESENT => PKCS11Token.Error.TokenNotPresent,
        .TOKEN_NOT_RECOGNIZED => PKCS11Token.Error.TokenNotRecognized,
        .TOKEN_WRITE_PROTECTED => PKCS11Token.Error.TokenWriteProhibited,
        .UNWRAPPING_KEY_HANDLE_INVALID => PKCS11Token.Error.UnwrappingKeyHandleInvalid,
        .UNWRAPPING_KEY_SIZE_RANGE => PKCS11Token.Error.UnwrappingKeySizeRange,
        .UNWRAPPING_KEY_TYPE_INCONSISTENT => PKCS11Token.Error.UnwrappingKeyTypeInconsistent,
        .USER_ALREADY_LOGGED_IN => PKCS11Token.Error.UserAlreadyLoggedIn,
        .USER_NOT_LOGGED_IN => PKCS11Token.Error.UserNotLoggedIn,
        .USER_PIN_NOT_INITIALIZED => PKCS11Token.Error.UserPINNotInitialized,
        .USER_TYPE_INVALID => PKCS11Token.Error.UserTypeInvalid,
        .USER_ANOTHER_ALREADY_LOGGED_IN => PKCS11Token.Error.UserAnotherAlreadyLoggedIn,
        .USER_TOO_MANY_TYPES => PKCS11Token.Error.UserTooManyTypes,
        .WRAPPED_KEY_INVALID => PKCS11Token.Error.WrappedKeyInvalid,
        .WRAPPED_KEY_LEN_RANGE => PKCS11Token.Error.WrappedKeyLenRange,
        .WRAPPING_KEY_HANDLE_INVALID => PKCS11Token.Error.WrappingKeyHandleInvalid,
        .WRAPPING_KEY_SIZE_RANGE => PKCS11Token.Error.WrappingKeySizeRange,
        .WRAPPING_KEY_TYPE_INCONSISTENT => PKCS11Token.Error.WrappingKeyTypeInconsistent,
        .RANDOM_SEED_NOT_SUPPORTED => PKCS11Token.Error.RandomSeedNotSupported,
        .RANDOM_NO_RNG => PKCS11Token.Error.RandomNoRNG,
        .DOMAIN_PARAMS_INVALID => PKCS11Token.Error.DomainParamsInvalid,
        .CURVE_NOT_SUPPORTED => PKCS11Token.Error.CurveNotSupported,
        .BUFFER_TOO_SMALL => PKCS11Token.Error.BufferTooSmall,
        .SAVED_STATE_INVALID => PKCS11Token.Error.SavedStateInvalid,
        .INFORMATION_SENSITIVE => PKCS11Token.Error.InformationSensitive,
        .STATE_UNSAVEABLE => PKCS11Token.Error.StateUnsavable,
        .CRYPTOKI_NOT_INITIALIZED => PKCS11Token.Error.CryptokiNotInitialized,
        .CRYPTOKI_ALREADY_INITIALIZED => PKCS11Token.Error.CryptokiAlreadyInitialized,
        .MUTEX_BAD => PKCS11Token.Error.MutexBad,
        .MUTEX_NOT_LOCKED => PKCS11Token.Error.MutexNotLocked,
        .NEW_PIN_MODE => PKCS11Token.Error.NewPINMode,
        .NEXT_OTP => PKCS11Token.Error.NextOTP,
        .EXCEEDED_MAX_ITERATIONS => PKCS11Token.Error.ExceededMaxIterations,
        .FIPS_SELF_TEST_FAILED => PKCS11Token.Error.FIPSSelfTestFailed,
        .LIBRARY_LOAD_FAILED => PKCS11Token.Error.LibraryLoadFailed,
        .PIN_TOO_WEAK => PKCS11Token.Error.PINTooWeak,
        .PUBLIC_KEY_INVALID => PKCS11Token.Error.PublicKeyInvalid,
        .FUNCTION_REJECTED => PKCS11Token.Error.FunctionRejected,
        else => PKCS11Token.Error.Unknown,
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

fn returnIfError(rv: c_ulong) PKCS11Token.Error!void {
    const result = decodeRv(rv);
    if (result != ReturnValue.OK) {
        return returnValueToError(result);
    }
}

fn decodeRv(rv: c_ulong) ReturnValue {
    return @enumFromInt(rv);
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
    var token = try PKCS11Token.init(testing.allocator, config.module);
    defer token.deinit();
    try token.initialize();
    const allocator = testing.allocator;

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
