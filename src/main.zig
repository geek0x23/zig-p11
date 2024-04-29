const std = @import("std");
const assert = std.debug.assert;
const config = @import("config");
const log = std.log.scoped(.p11);
const testing = std.testing;

const print = std.debug.print;

const cryptoki = @cImport({
    @cInclude("cryptoki.h");
});

pub const PKCS11Token = struct {
    module: *std.DynLib = undefined,
    funcs: *cryptoki.CK_FUNCTION_LIST = undefined,

    pub fn init(path: []const u8) !PKCS11Token {
        log.debug("Loading PKCS#11 library from path: {s}\n", .{path});
        var module = try std.DynLib.open(path);
        errdefer module.close();

        log.debug("Obtaining function list from PKCS#11 runtime.\n", .{});
        var p11funcs: cryptoki.CK_FUNCTION_LIST_PTR = undefined;
        const getFunctionList = module.lookup(cryptoki.CK_C_GetFunctionList, "C_GetFunctionList").?.?;

        const rv = getFunctionList(&p11funcs);
        const result = decodeRv(rv);
        if (result != ReturnValue.OK) {
            return returnValueToError(result);
        }

        return PKCS11Token{ .funcs = p11funcs, .module = &module };
    }

    pub fn close(self: @This()) void {
        self.module.close();
    }

    pub fn initialize(self: @This()) Error!void {
        var args: cryptoki.CK_C_INITIALIZE_ARGS = .{ .flags = cryptoki.CKF_OS_LOCKING_OK };
        const rv = self.funcs.C_Initialize.?(&args);
        const result = decodeRv(rv);
        if (result != ReturnValue.OK) {
            return returnValueToError(result);
        }
    }

    pub fn finalize(self: @This()) Error!void {
        const args: cryptoki.CK_VOID_PTR = null;
        const rv = self.funcs.C_Finalize.?(args);
        const result = decodeRv(rv);
        if (result != ReturnValue.OK) {
            return returnValueToError(result);
        }
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
    OK = cryptoki.CKR_OK,
    CANCEL = cryptoki.CKR_CANCEL,
    HOST_MEMORY = cryptoki.CKR_HOST_MEMORY,
    SLOT_ID_INVALID = cryptoki.CKR_SLOT_ID_INVALID,
    GENERAL_ERROR = cryptoki.CKR_GENERAL_ERROR,
    FUNCTION_FAILED = cryptoki.CKR_FUNCTION_FAILED,
    ARGUMENTS_BAD = cryptoki.CKR_ARGUMENTS_BAD,
    NO_EVENT = cryptoki.CKR_NO_EVENT,
    NEED_TO_CREATE_THREADS = cryptoki.CKR_NEED_TO_CREATE_THREADS,
    CANT_LOCK = cryptoki.CKR_CANT_LOCK,
    ATTRIBUTE_READ_ONLY = cryptoki.CKR_ATTRIBUTE_READ_ONLY,
    ATTRIBUTE_SENSITIVE = cryptoki.CKR_ATTRIBUTE_SENSITIVE,
    ATTRIBUTE_TYPE_INVALID = cryptoki.CKR_ATTRIBUTE_TYPE_INVALID,
    ATTRIBUTE_VALUE_INVALID = cryptoki.CKR_ATTRIBUTE_VALUE_INVALID,
    ACTION_PROHIBITED = cryptoki.CKR_ACTION_PROHIBITED,
    DATA_INVALID = cryptoki.CKR_DATA_INVALID,
    DATA_LEN_RANGE = cryptoki.CKR_DATA_LEN_RANGE,
    DEVICE_ERROR = cryptoki.CKR_DEVICE_ERROR,
    DEVICE_MEMORY = cryptoki.CKR_DEVICE_MEMORY,
    DEVICE_REMOVED = cryptoki.CKR_DEVICE_REMOVED,
    ENCRYPTED_DATA_INVALID = cryptoki.CKR_ENCRYPTED_DATA_INVALID,
    ENCRYPTED_DATA_LEN_RANGE = cryptoki.CKR_ENCRYPTED_DATA_LEN_RANGE,
    FUNCTION_CANCELED = cryptoki.CKR_FUNCTION_CANCELED,
    FUNCTION_NOT_PARALLEL = cryptoki.CKR_FUNCTION_NOT_PARALLEL,
    FUNCTION_NOT_SUPPORTED = cryptoki.CKR_FUNCTION_NOT_SUPPORTED,
    KEY_HANDLE_INVALID = cryptoki.CKR_KEY_HANDLE_INVALID,
    KEY_SIZE_RANGE = cryptoki.CKR_KEY_SIZE_RANGE,
    KEY_TYPE_INCONSISTENT = cryptoki.CKR_KEY_TYPE_INCONSISTENT,
    KEY_NOT_NEEDED = cryptoki.CKR_KEY_NOT_NEEDED,
    KEY_CHANGED = cryptoki.CKR_KEY_CHANGED,
    KEY_NEEDED = cryptoki.CKR_KEY_NEEDED,
    KEY_INDIGESTIBLE = cryptoki.CKR_KEY_INDIGESTIBLE,
    KEY_FUNCTION_NOT_PERMITTED = cryptoki.CKR_KEY_FUNCTION_NOT_PERMITTED,
    KEY_NOT_WRAPPABLE = cryptoki.CKR_KEY_NOT_WRAPPABLE,
    KEY_UNEXTRACTABLE = cryptoki.CKR_KEY_UNEXTRACTABLE,
    MECHANISM_INVALID = cryptoki.CKR_MECHANISM_INVALID,
    MECHANISM_PARAM_INVALID = cryptoki.CKR_MECHANISM_PARAM_INVALID,
    OBJECT_HANDLE_INVALID = cryptoki.CKR_OBJECT_HANDLE_INVALID,
    OPERATION_ACTIVE = cryptoki.CKR_OPERATION_ACTIVE,
    OPERATION_NOT_INITIALIZED = cryptoki.CKR_OPERATION_NOT_INITIALIZED,
    PIN_INCORRECT = cryptoki.CKR_PIN_INCORRECT,
    PIN_INVALID = cryptoki.CKR_PIN_INVALID,
    PIN_LEN_RANGE = cryptoki.CKR_PIN_LEN_RANGE,
    PIN_EXPIRED = cryptoki.CKR_PIN_EXPIRED,
    PIN_LOCKED = cryptoki.CKR_PIN_LOCKED,
    SESSION_CLOSED = cryptoki.CKR_SESSION_CLOSED,
    SESSION_COUNT = cryptoki.CKR_SESSION_COUNT,
    SESSION_HANDLE_INVALID = cryptoki.CKR_SESSION_HANDLE_INVALID,
    SESSION_PARALLEL_NOT_SUPPORTED = cryptoki.CKR_SESSION_PARALLEL_NOT_SUPPORTED,
    SESSION_READ_ONLY = cryptoki.CKR_SESSION_READ_ONLY,
    SESSION_EXISTS = cryptoki.CKR_SESSION_EXISTS,
    SESSION_READ_ONLY_EXISTS = cryptoki.CKR_SESSION_READ_ONLY_EXISTS,
    SESSION_READ_WRITE_SO_EXISTS = cryptoki.CKR_SESSION_READ_WRITE_SO_EXISTS,
    SIGNATURE_INVALID = cryptoki.CKR_SIGNATURE_INVALID,
    SIGNATURE_LEN_RANGE = cryptoki.CKR_SIGNATURE_LEN_RANGE,
    TEMPLATE_INCOMPLETE = cryptoki.CKR_TEMPLATE_INCOMPLETE,
    TEMPLATE_INCONSISTENT = cryptoki.CKR_TEMPLATE_INCONSISTENT,
    TOKEN_NOT_PRESENT = cryptoki.CKR_TOKEN_NOT_PRESENT,
    TOKEN_NOT_RECOGNIZED = cryptoki.CKR_TOKEN_NOT_RECOGNIZED,
    TOKEN_WRITE_PROTECTED = cryptoki.CKR_TOKEN_WRITE_PROTECTED,
    UNWRAPPING_KEY_HANDLE_INVALID = cryptoki.CKR_UNWRAPPING_KEY_HANDLE_INVALID,
    UNWRAPPING_KEY_SIZE_RANGE = cryptoki.CKR_UNWRAPPING_KEY_SIZE_RANGE,
    UNWRAPPING_KEY_TYPE_INCONSISTENT = cryptoki.CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT,
    USER_ALREADY_LOGGED_IN = cryptoki.CKR_USER_ALREADY_LOGGED_IN,
    USER_NOT_LOGGED_IN = cryptoki.CKR_USER_NOT_LOGGED_IN,
    USER_PIN_NOT_INITIALIZED = cryptoki.CKR_USER_PIN_NOT_INITIALIZED,
    USER_TYPE_INVALID = cryptoki.CKR_USER_TYPE_INVALID,
    USER_ANOTHER_ALREADY_LOGGED_IN = cryptoki.CKR_USER_ANOTHER_ALREADY_LOGGED_IN,
    USER_TOO_MANY_TYPES = cryptoki.CKR_USER_TOO_MANY_TYPES,
    WRAPPED_KEY_INVALID = cryptoki.CKR_WRAPPED_KEY_INVALID,
    WRAPPED_KEY_LEN_RANGE = cryptoki.CKR_WRAPPED_KEY_LEN_RANGE,
    WRAPPING_KEY_HANDLE_INVALID = cryptoki.CKR_WRAPPING_KEY_HANDLE_INVALID,
    WRAPPING_KEY_SIZE_RANGE = cryptoki.CKR_WRAPPING_KEY_SIZE_RANGE,
    WRAPPING_KEY_TYPE_INCONSISTENT = cryptoki.CKR_WRAPPING_KEY_TYPE_INCONSISTENT,
    RANDOM_SEED_NOT_SUPPORTED = cryptoki.CKR_RANDOM_SEED_NOT_SUPPORTED,
    RANDOM_NO_RNG = cryptoki.CKR_RANDOM_NO_RNG,
    DOMAIN_PARAMS_INVALID = cryptoki.CKR_DOMAIN_PARAMS_INVALID,
    CURVE_NOT_SUPPORTED = cryptoki.CKR_CURVE_NOT_SUPPORTED,
    BUFFER_TOO_SMALL = cryptoki.CKR_BUFFER_TOO_SMALL,
    SAVED_STATE_INVALID = cryptoki.CKR_SAVED_STATE_INVALID,
    INFORMATION_SENSITIVE = cryptoki.CKR_INFORMATION_SENSITIVE,
    STATE_UNSAVEABLE = cryptoki.CKR_STATE_UNSAVEABLE,
    CRYPTOKI_NOT_INITIALIZED = cryptoki.CKR_CRYPTOKI_NOT_INITIALIZED,
    CRYPTOKI_ALREADY_INITIALIZED = cryptoki.CKR_CRYPTOKI_ALREADY_INITIALIZED,
    MUTEX_BAD = cryptoki.CKR_MUTEX_BAD,
    MUTEX_NOT_LOCKED = cryptoki.CKR_MUTEX_NOT_LOCKED,
    NEW_PIN_MODE = cryptoki.CKR_NEW_PIN_MODE,
    NEXT_OTP = cryptoki.CKR_NEXT_OTP,
    EXCEEDED_MAX_ITERATIONS = cryptoki.CKR_EXCEEDED_MAX_ITERATIONS,
    FIPS_SELF_TEST_FAILED = cryptoki.CKR_FIPS_SELF_TEST_FAILED,
    LIBRARY_LOAD_FAILED = cryptoki.CKR_LIBRARY_LOAD_FAILED,
    PIN_TOO_WEAK = cryptoki.CKR_PIN_TOO_WEAK,
    PUBLIC_KEY_INVALID = cryptoki.CKR_PUBLIC_KEY_INVALID,
    FUNCTION_REJECTED = cryptoki.CKR_FUNCTION_REJECTED,
    VENDOR_DEFINED = cryptoki.CKR_VENDOR_DEFINED,
};

fn decodeRv(rv: c_ulong) ReturnValue {
    return @enumFromInt(rv);
}

test "it can load and close a PKCS#11 library." {
    const token = try PKCS11Token.init(config.module);
    token.close();
}

test "it can initialize and finalize the token." {
    const token = try PKCS11Token.init(config.module);
    defer token.close();

    try token.initialize();
    try token.finalize();
}
