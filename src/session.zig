const std = @import("std");
const err = @import("err.zig");
const helpers = @import("helpers.zig");
const pkcs11 = @import("pkcs11.zig");

const Allocator = std.mem.Allocator;
const C = pkcs11.C;
const Context = pkcs11.Context;
const Error = err.Error;

pub const Object = struct {
    handle: c_ulong,

    fn fromCType(handle: C.CK_OBJECT_HANDLE) Object {
        return .{ .handle = handle };
    }
};

pub const ObjectClass = enum(c_ulong) {
    data = C.CKO_DATA,
    certificate = C.CKO_CERTIFICATE,
    public_key = C.CKO_PUBLIC_KEY,
    private_key = C.CKO_PRIVATE_KEY,
    secret_key = C.CKO_SECRET_KEY,
    hw_feature = C.CKO_HW_FEATURE,
    domain_parameters = C.CKO_DOMAIN_PARAMETERS,
    mechanism = C.CKO_MECHANISM,
    otp_key = C.CKO_OTP_KEY,
    vendor_defined = C.CKO_VENDOR_DEFINED,
};

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

pub const OTPFormatAttributeValue = enum(c_ulong) {
    decimal = C.CK_OTP_FORMAT_DECIMAL,
    hexadecimal = C.CK_OTP_FORMAT_HEXADECIMAL,
    alphanumeric = C.CK_OTP_FORMAT_ALPHANUMERIC,
    binary = C.CK_OTP_FORMAT_BINARY,
};

pub const OTPParameterAttributeValue = enum(c_ulong) {
    ignored = C.CK_OTP_PARAM_IGNORED,
    optional = C.CK_OTP_PARAM_OPTIONAL,
    mandatory = C.CK_OTP_PARAM_MANDATORY,
};

pub const AttributeType = enum(c_ulong) {
    class = C.CKA_CLASS,
    token = C.CKA_TOKEN,
    private = C.CKA_PRIVATE,
    label = C.CKA_LABEL,
    application = C.CKA_APPLICATION,
    value = C.CKA_VALUE,
    object_id = C.CKA_OBJECT_ID,
    certificate_type = C.CKA_CERTIFICATE_TYPE,
    issuer = C.CKA_ISSUER,
    serial_number = C.CKA_SERIAL_NUMBER,
    ac_issuer = C.CKA_AC_ISSUER,
    owner = C.CKA_OWNER,
    attr_types = C.CKA_ATTR_TYPES,
    trusted = C.CKA_TRUSTED,
    certificate_category = C.CKA_CERTIFICATE_CATEGORY,
    java_midp_security_domain = C.CKA_JAVA_MIDP_SECURITY_DOMAIN,
    url = C.CKA_URL,
    hash_of_subject_public_key = C.CKA_HASH_OF_SUBJECT_PUBLIC_KEY,
    hash_of_issuer_public_key = C.CKA_HASH_OF_ISSUER_PUBLIC_KEY,
    name_hash_algorithm = C.CKA_NAME_HASH_ALGORITHM,
    check_value = C.CKA_CHECK_VALUE,
    key_type = C.CKA_KEY_TYPE,
    subject = C.CKA_SUBJECT,
    id = C.CKA_ID,
    sensitive = C.CKA_SENSITIVE,
    encrypt = C.CKA_ENCRYPT,
    decrypt = C.CKA_DECRYPT,
    wrap = C.CKA_WRAP,
    unwrap = C.CKA_UNWRAP,
    sign = C.CKA_SIGN,
    sign_recover = C.CKA_SIGN_RECOVER,
    verify = C.CKA_VERIFY,
    verify_recover = C.CKA_VERIFY_RECOVER,
    derive = C.CKA_DERIVE,
    start_date = C.CKA_START_DATE,
    end_date = C.CKA_END_DATE,
    modulus = C.CKA_MODULUS,
    modulus_bits = C.CKA_MODULUS_BITS,
    public_exponent = C.CKA_PUBLIC_EXPONENT,
    private_exponent = C.CKA_PRIVATE_EXPONENT,
    prime_1 = C.CKA_PRIME_1,
    prime_2 = C.CKA_PRIME_2,
    exponent_1 = C.CKA_EXPONENT_1,
    exponent_2 = C.CKA_EXPONENT_2,
    coefficient = C.CKA_COEFFICIENT,
    public_key_info = C.CKA_PUBLIC_KEY_INFO,
    prime = C.CKA_PRIME,
    subprime = C.CKA_SUBPRIME,
    base = C.CKA_BASE,
    prime_bits = C.CKA_PRIME_BITS,
    sub_prime_bits = C.CKA_SUB_PRIME_BITS,
    value_bits = C.CKA_VALUE_BITS,
    value_len = C.CKA_VALUE_LEN,
    extractable = C.CKA_EXTRACTABLE,
    local = C.CKA_LOCAL,
    never_extractable = C.CKA_NEVER_EXTRACTABLE,
    always_sensitive = C.CKA_ALWAYS_SENSITIVE,
    key_gen_mechanism = C.CKA_KEY_GEN_MECHANISM,
    modifiable = C.CKA_MODIFIABLE,
    copyable = C.CKA_COPYABLE,
    destroyable = C.CKA_DESTROYABLE,
    ec_params = C.CKA_EC_PARAMS,
    ec_point = C.CKA_EC_POINT,
    secondary_auth = C.CKA_SECONDARY_AUTH,
    auth_pin_flags = C.CKA_AUTH_PIN_FLAGS,
    always_authenticate = C.CKA_ALWAYS_AUTHENTICATE,
    wrap_with_trusted = C.CKA_WRAP_WITH_TRUSTED,
    wrap_template = C.CKA_WRAP_TEMPLATE,
    unwrap_template = C.CKA_UNWRAP_TEMPLATE,
    derive_template = C.CKA_DERIVE_TEMPLATE,
    otp_format = C.CKA_OTP_FORMAT,
    otp_length = C.CKA_OTP_LENGTH,
    otp_time_interval = C.CKA_OTP_TIME_INTERVAL,
    otp_user_friendly_mode = C.CKA_OTP_USER_FRIENDLY_MODE,
    otp_challenge_requirement = C.CKA_OTP_CHALLENGE_REQUIREMENT,
    otp_time_requirement = C.CKA_OTP_TIME_REQUIREMENT,
    otp_counter_requirement = C.CKA_OTP_COUNTER_REQUIREMENT,
    otp_pin_requirement = C.CKA_OTP_PIN_REQUIREMENT,
    otp_counter = C.CKA_OTP_COUNTER,
    otp_time = C.CKA_OTP_TIME,
    otp_user_identifier = C.CKA_OTP_USER_IDENTIFIER,
    otp_service_identifier = C.CKA_OTP_SERVICE_IDENTIFIER,
    otp_service_logo = C.CKA_OTP_SERVICE_LOGO,
    otp_service_logo_type = C.CKA_OTP_SERVICE_LOGO_TYPE,
    gostr3410_params = C.CKA_GOSTR3410_PARAMS,
    gostr3411_params = C.CKA_GOSTR3411_PARAMS,
    gost28147_params = C.CKA_GOST28147_PARAMS,
    hw_feature_type = C.CKA_HW_FEATURE_TYPE,
    reset_on_init = C.CKA_RESET_ON_INIT,
    has_reset = C.CKA_HAS_RESET,
    pixel_x = C.CKA_PIXEL_X,
    pixel_y = C.CKA_PIXEL_Y,
    resolution = C.CKA_RESOLUTION,
    char_rows = C.CKA_CHAR_ROWS,
    char_columns = C.CKA_CHAR_COLUMNS,
    color = C.CKA_COLOR,
    bits_per_pixel = C.CKA_BITS_PER_PIXEL,
    char_sets = C.CKA_CHAR_SETS,
    encoding_methods = C.CKA_ENCODING_METHODS,
    mime_types = C.CKA_MIME_TYPES,
    mechanism_type = C.CKA_MECHANISM_TYPE,
    required_cms_attributes = C.CKA_REQUIRED_CMS_ATTRIBUTES,
    default_cms_attributes = C.CKA_DEFAULT_CMS_ATTRIBUTES,
    supported_cms_attributes = C.CKA_SUPPORTED_CMS_ATTRIBUTES,
    allowed_mechanisms = C.CKA_ALLOWED_MECHANISMS,
    vendor_defined = C.CKA_VENDOR_DEFINED,
};

pub const Attribute = struct {
    type: AttributeType,
    value: []const u8,

    pub fn new(attr_type: AttributeType, value: anytype) Attribute {
        const sliced_value: []const u8 = switch (@TypeOf(value)) {
            bool => if (value) &[_]u8{0x00000001} else &[_]u8{0x00000001},
            ObjectClass => std.mem.asBytes(&@intFromEnum(value)),
            else => value,
        };

        return .{ .type = attr_type, .value = sliced_value };
    }
};

pub const AttributeFlags = struct {
    array: bool = false,

    fn fromCType(flags: C.CK_FLAGS) AttributeFlags {
        return .{
            .array = (flags & C.CKF_ARRAY_ATTRIBUTE) == C.CKF_ARRAY_ATTRIBUTE,
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

    pub fn createObject(self: Session, template: []const Attribute) Error!Object {
        const allocator = std.heap.c_allocator;
        var handle: c_ulong = 0;

        const c_template: []C.CK_ATTRIBUTE = try allocator.alloc(C.CK_ATTRIBUTE, template.len);
        defer allocator.free(c_template);

        for (template, 0..) |attr, i| {
            c_template[i] = C.CK_ATTRIBUTE{
                .type = @intFromEnum(attr.type),
                .pValue = @constCast(attr.value.ptr),
                .ulValueLen = attr.value.len,
            };
        }

        const rv = self.ctx.sym.C_CreateObject.?(self.handle, @ptrCast(c_template), c_template.len, &handle);
        try helpers.returnIfError(rv);

        return Object.fromCType(handle);
    }
};
