const std = @import("std");
const builtin = @import("builtin");
const log = std.log.scoped(.p11);
const testing = std.testing;
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const print = std.debug.print;

// I like seeing logs in tests, shoot me.
pub const std_options = .{
    .log_level = if (builtin.is_test) std.log.Level.debug else std.log.Level.warn,
};

const C = @cImport({
    @cInclude("cryptoki.h");
});

pub const PKCS11Token = struct {
    funcs: *C.CK_FUNCTION_LIST,
    mutex: std.Thread.Mutex = std.Thread.Mutex{},

    /// Opens the given PKCS#11 library and loads symbols from it.
    pub fn init(path: []const u8) !PKCS11Token {
        log.warn("Loading PKCS#11 library from path: {s}", .{path});
        var module = try std.DynLib.open(path);
        defer module.close();

        var p11funcs: C.CK_FUNCTION_LIST_PTR = undefined;
        const getFunctionList = module.lookup(C.CK_C_GetFunctionList, "C_GetFunctionList").?.?;
        const rv = getFunctionList(&p11funcs);

        try returnIfError(rv);

        return .{ .funcs = p11funcs };
    }

    /// Initializes the PKCS#11 module.
    pub fn initialize(self: *PKCS11Token) Error!void {
        var args: C.CK_C_INITIALIZE_ARGS = .{ .flags = C.CKF_OS_LOCKING_OK };
        const rv = self.funcs.C_Initialize.?(&args);
        try returnIfError(rv);
    }

    /// Finalizes the PKCS#11 module.
    pub fn finalize(self: *const PKCS11Token) Error!void {
        const args: C.CK_VOID_PTR = null;
        const rv = self.funcs.C_Finalize.?(args);
        try returnIfError(rv);
    }

    /// Caller must free returned memory.
    /// Retrieves a slot list.
    pub fn getSlotList(self: *const PKCS11Token, allocator: *const Allocator, tokenPresent: bool) Error![]usize {
        const present: C.CK_BBOOL = if (tokenPresent) C.CK_TRUE else C.CK_FALSE;
        var slotCount: C.CK_ULONG = undefined;

        var rv = self.funcs.C_GetSlotList.?(present, null, &slotCount);
        try returnIfError(rv);

        const slotList = try allocator.alloc(C.CK_ULONG, slotCount);
        rv = self.funcs.C_GetSlotList.?(present, slotList.ptr, &slotCount);
        try returnIfError(rv);

        return slotList;
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
    _ = try PKCS11Token.init("/lib64/softhsm/libsofthsm.so");
}

test "it can initialize and finalize the token." {
    var token = try PKCS11Token.init("/lib64/softhsm/libsofthsm.so");

    try token.initialize();
    try token.finalize();
}

test "it can get a slot list." {
    var token = try PKCS11Token.init("/lib64/softhsm/libsofthsm.so");

    token.initialize() catch {};

    const allocator = &testing.allocator;
    const slots = try token.getSlotList(allocator, false);
    defer allocator.free(slots);

    try testing.expect(slots.len > 0);
}
