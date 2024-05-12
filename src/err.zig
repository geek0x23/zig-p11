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
