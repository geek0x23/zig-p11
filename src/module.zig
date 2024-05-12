const builtin = @import("builtin");
const config = @import("config");
const helpers = @import("helpers.zig");
const pkcs11 = @import("pkcs11.zig");
const session = @import("session.zig");
const std = @import("std");

const Allocator = std.mem.Allocator;
const C = pkcs11.C;
const Context = pkcs11.Context;
const Error = @import("err.zig").Error;
const Session = session.Session;
const SessionFlags = session.SessionFlags;

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
            .hardware_slot = (flags & C.CKF_HW_SLOT) == C.CKF_HW_SLOT,
            .removable_device = (flags & C.CKF_REMOVABLE_DEVICE) == C.CKF_REMOVABLE_DEVICE,
            .token_present = (flags & C.CKF_TOKEN_PRESENT) == C.CKF_TOKEN_PRESENT,
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
            .rng = (flags & C.CKF_RNG) == C.CKF_RNG,
            .write_protected = (flags & C.CKF_WRITE_PROTECTED) == C.CKF_WRITE_PROTECTED,
            .login_required = (flags & C.CKF_LOGIN_REQUIRED) == C.CKF_LOGIN_REQUIRED,
            .user_pin_initialized = (flags & C.CKF_USER_PIN_INITIALIZED) == C.CKF_USER_PIN_INITIALIZED,
            .restore_key_not_needed = (flags & C.CKF_RESTORE_KEY_NOT_NEEDED) == C.CKF_RESTORE_KEY_NOT_NEEDED,
            .clock_on_token = (flags & C.CKF_CLOCK_ON_TOKEN) == C.CKF_CLOCK_ON_TOKEN,
            .protected_authentication_path = (flags & C.CKF_PROTECTED_AUTHENTICATION_PATH) == C.CKF_PROTECTED_AUTHENTICATION_PATH,
            .dual_crypto_operations = (flags & C.CKF_DUAL_CRYPTO_OPERATIONS) == C.CKF_DUAL_CRYPTO_OPERATIONS,
            .token_initialized = (flags & C.CKF_TOKEN_INITIALIZED) == C.CKF_TOKEN_INITIALIZED,
            .secondary_authentication = (flags & C.CKF_SECONDARY_AUTHENTICATION) == C.CKF_SECONDARY_AUTHENTICATION,
            .user_pin_count_low = (flags & C.CKF_USER_PIN_COUNT_LOW) == C.CKF_USER_PIN_COUNT_LOW,
            .user_pin_final_try = (flags & C.CKF_USER_PIN_FINAL_TRY) == C.CKF_USER_PIN_FINAL_TRY,
            .user_pin_locked = (flags & C.CKF_USER_PIN_LOCKED) == C.CKF_USER_PIN_LOCKED,
            .user_pin_to_be_changed = (flags & C.CKF_USER_PIN_TO_BE_CHANGED) == C.CKF_USER_PIN_TO_BE_CHANGED,
            .so_pin_count_low = (flags & C.CKF_SO_PIN_COUNT_LOW) == C.CKF_SO_PIN_COUNT_LOW,
            .so_pin_final_try = (flags & C.CKF_SO_PIN_FINAL_TRY) == C.CKF_SO_PIN_FINAL_TRY,
            .so_pin_locked = (flags & C.CKF_SO_PIN_LOCKED) == C.CKF_SO_PIN_LOCKED,
            .so_pin_to_be_changed = (flags & C.CKF_SO_PIN_TO_BE_CHANGED) == C.CKF_SO_PIN_TO_BE_CHANGED,
        };
    }
};

pub const MechanismInfo = struct {
    min_key_size: c_ulong,
    max_key_size: c_ulong,
    flags: MechanismFlags,

    fn fromCType(info: C.CK_MECHANISM_INFO) MechanismInfo {
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

    fn fromCType(flags: C.CK_FLAGS) MechanismFlags {
        return .{
            .hardware = (flags & C.CKF_HW) == C.CKF_HW,
            .encrypt = (flags & C.CKF_ENCRYPT) == C.CKF_ENCRYPT,
            .decrypt = (flags & C.CKF_DECRYPT) == C.CKF_DECRYPT,
            .digest = (flags & C.CKF_DIGEST) == C.CKF_DIGEST,
            .sign = (flags & C.CKF_SIGN) == C.CKF_SIGN,
            .sign_with_recovery = (flags & C.CKF_SIGN_RECOVER) == C.CKF_SIGN_RECOVER,
            .verify = (flags & C.CKF_VERIFY) == C.CKF_VERIFY,
            .verify_with_recovery = (flags & C.CKF_VERIFY_RECOVER) == C.CKF_VERIFY_RECOVER,
            .generate = (flags & C.CKF_GENERATE) == C.CKF_GENERATE,
            .generate_key_pair = (flags & C.CKF_GENERATE_KEY_PAIR) == C.CKF_GENERATE_KEY_PAIR,
            .wrap = (flags & C.CKF_WRAP) == C.CKF_WRAP,
            .unwrap = (flags & C.CKF_UNWRAP) == C.CKF_UNWRAP,
            .derive = (flags & C.CKF_DERIVE) == C.CKF_DERIVE,
            .ec = MechanismECFlags.fromCType(flags),
            .extension = (flags & C.CKF_EXTENSION) == C.CKF_EXTENSION,
        };
    }
};

pub const MechanismECFlags = struct {
    f_p: bool = false,
    named_curve: bool = false,
    uncompress: bool = false,
    compress: bool = false,

    fn fromCType(flags: C.CK_FLAGS) MechanismECFlags {
        return .{
            .f_p = (flags & C.CKF_EC_F_P) == C.CKF_EC_F_P,
            .named_curve = (flags & C.CKF_EC_NAMEDCURVE) == C.CKF_EC_NAMEDCURVE,
            .uncompress = (flags & C.CKF_EC_UNCOMPRESS) == C.CKF_EC_UNCOMPRESS,
            .compress = (flags & C.CKF_EC_COMPRESS) == C.CKF_EC_COMPRESS,
        };
    }
};

pub const MechanismType = enum(c_ulong) {
    rsa_pkcs_key_pair_gen = C.CKM_RSA_PKCS_KEY_PAIR_GEN,
    rsa_pkcs = C.CKM_RSA_PKCS,
    rsa_9796 = C.CKM_RSA_9796,
    rsa_x_509 = C.CKM_RSA_X_509,
    md2_rsa_pkcs = C.CKM_MD2_RSA_PKCS,
    md5_rsa_pkcs = C.CKM_MD5_RSA_PKCS,
    sha1_rsa_pkcs = C.CKM_SHA1_RSA_PKCS,
    ripemd128_rsa_pkcs = C.CKM_RIPEMD128_RSA_PKCS,
    ripemd160_rsa_pkcs = C.CKM_RIPEMD160_RSA_PKCS,
    rsa_pkcs_oaep = C.CKM_RSA_PKCS_OAEP,
    rsa_x9_31_key_pair_gen = C.CKM_RSA_X9_31_KEY_PAIR_GEN,
    rsa_x9_31 = C.CKM_RSA_X9_31,
    sha1_rsa_x9_31 = C.CKM_SHA1_RSA_X9_31,
    rsa_pkcs_pss = C.CKM_RSA_PKCS_PSS,
    sha1_rsa_pkcs_pss = C.CKM_SHA1_RSA_PKCS_PSS,
    dsa_key_pair_gen = C.CKM_DSA_KEY_PAIR_GEN,
    dsa = C.CKM_DSA,
    dsa_sha1 = C.CKM_DSA_SHA1,
    dsa_sha224 = C.CKM_DSA_SHA224,
    dsa_sha256 = C.CKM_DSA_SHA256,
    dsa_sha384 = C.CKM_DSA_SHA384,
    dsa_sha512 = C.CKM_DSA_SHA512,
    dh_pkcs_key_pair_gen = C.CKM_DH_PKCS_KEY_PAIR_GEN,
    dh_pkcs_derive = C.CKM_DH_PKCS_DERIVE,
    x9_42_dh_key_pair_gen = C.CKM_X9_42_DH_KEY_PAIR_GEN,
    x9_42_dh_derive = C.CKM_X9_42_DH_DERIVE,
    x9_42_dh_hybrid_derive = C.CKM_X9_42_DH_HYBRID_DERIVE,
    x9_42_mqv_derive = C.CKM_X9_42_MQV_DERIVE,
    sha256_rsa_pkcs = C.CKM_SHA256_RSA_PKCS,
    sha384_rsa_pkcs = C.CKM_SHA384_RSA_PKCS,
    sha512_rsa_pkcs = C.CKM_SHA512_RSA_PKCS,
    sha256_rsa_pkcs_pss = C.CKM_SHA256_RSA_PKCS_PSS,
    sha384_rsa_pkcs_pss = C.CKM_SHA384_RSA_PKCS_PSS,
    sha512_rsa_pkcs_pss = C.CKM_SHA512_RSA_PKCS_PSS,
    sha512_224 = C.CKM_SHA512_224,
    sha512_224_hmac = C.CKM_SHA512_224_HMAC,
    sha512_224_hmac_general = C.CKM_SHA512_224_HMAC_GENERAL,
    sha512_224_key_derivation = C.CKM_SHA512_224_KEY_DERIVATION,
    sha512_256 = C.CKM_SHA512_256,
    sha512_256_hmac = C.CKM_SHA512_256_HMAC,
    sha512_256_hmac_general = C.CKM_SHA512_256_HMAC_GENERAL,
    sha512_256_key_derivation = C.CKM_SHA512_256_KEY_DERIVATION,
    sha512_t = C.CKM_SHA512_T,
    sha512_t_hmac = C.CKM_SHA512_T_HMAC,
    sha512_t_hmac_general = C.CKM_SHA512_T_HMAC_GENERAL,
    sha512_t_key_derivation = C.CKM_SHA512_T_KEY_DERIVATION,
    rc2_key_gen = C.CKM_RC2_KEY_GEN,
    rc2_ecb = C.CKM_RC2_ECB,
    rc2_cbc = C.CKM_RC2_CBC,
    rc2_mac = C.CKM_RC2_MAC,
    rc2_mac_general = C.CKM_RC2_MAC_GENERAL,
    rc2_cbc_pad = C.CKM_RC2_CBC_PAD,
    rc4_key_gen = C.CKM_RC4_KEY_GEN,
    rc4 = C.CKM_RC4,
    des_key_gen = C.CKM_DES_KEY_GEN,
    des_ecb = C.CKM_DES_ECB,
    des_cbc = C.CKM_DES_CBC,
    des_mac = C.CKM_DES_MAC,
    des_mac_general = C.CKM_DES_MAC_GENERAL,
    des_cbc_pad = C.CKM_DES_CBC_PAD,
    des2_key_gen = C.CKM_DES2_KEY_GEN,
    des3_key_gen = C.CKM_DES3_KEY_GEN,
    des3_ecb = C.CKM_DES3_ECB,
    des3_cbc = C.CKM_DES3_CBC,
    des3_mac = C.CKM_DES3_MAC,
    des3_mac_general = C.CKM_DES3_MAC_GENERAL,
    des3_cbc_pad = C.CKM_DES3_CBC_PAD,
    des3_cmac_general = C.CKM_DES3_CMAC_GENERAL,
    des3_cmac = C.CKM_DES3_CMAC,
    cdmf_key_gen = C.CKM_CDMF_KEY_GEN,
    cdmf_ecb = C.CKM_CDMF_ECB,
    cdmf_cbc = C.CKM_CDMF_CBC,
    cdmf_mac = C.CKM_CDMF_MAC,
    cdmf_mac_general = C.CKM_CDMF_MAC_GENERAL,
    cdmf_cbc_pad = C.CKM_CDMF_CBC_PAD,
    des_ofb64 = C.CKM_DES_OFB64,
    des_ofb8 = C.CKM_DES_OFB8,
    des_cfb64 = C.CKM_DES_CFB64,
    des_cfb8 = C.CKM_DES_CFB8,
    md2 = C.CKM_MD2,
    md2_hmac = C.CKM_MD2_HMAC,
    md2_hmac_general = C.CKM_MD2_HMAC_GENERAL,
    md5 = C.CKM_MD5,
    md5_hmac = C.CKM_MD5_HMAC,
    md5_hmac_general = C.CKM_MD5_HMAC_GENERAL,
    sha_1 = C.CKM_SHA_1,
    sha_1_hmac = C.CKM_SHA_1_HMAC,
    sha_1_hmac_general = C.CKM_SHA_1_HMAC_GENERAL,
    ripemd128 = C.CKM_RIPEMD128,
    ripemd128_hmac = C.CKM_RIPEMD128_HMAC,
    ripemd128_hmac_general = C.CKM_RIPEMD128_HMAC_GENERAL,
    ripemd160 = C.CKM_RIPEMD160,
    ripemd160_hmac = C.CKM_RIPEMD160_HMAC,
    ripemd160_hmac_general = C.CKM_RIPEMD160_HMAC_GENERAL,
    sha256 = C.CKM_SHA256,
    sha256_hmac = C.CKM_SHA256_HMAC,
    sha256_hmac_general = C.CKM_SHA256_HMAC_GENERAL,
    sha384 = C.CKM_SHA384,
    sha384_hmac = C.CKM_SHA384_HMAC,
    sha384_hmac_general = C.CKM_SHA384_HMAC_GENERAL,
    sha512 = C.CKM_SHA512,
    sha512_hmac = C.CKM_SHA512_HMAC,
    sha512_hmac_general = C.CKM_SHA512_HMAC_GENERAL,
    securid_key_gen = C.CKM_SECURID_KEY_GEN,
    securid = C.CKM_SECURID,
    hotp_key_gen = C.CKM_HOTP_KEY_GEN,
    hotp = C.CKM_HOTP,
    acti = C.CKM_ACTI,
    acti_key_gen = C.CKM_ACTI_KEY_GEN,
    cast_key_gen = C.CKM_CAST_KEY_GEN,
    cast_ecb = C.CKM_CAST_ECB,
    cast_cbc = C.CKM_CAST_CBC,
    cast_mac = C.CKM_CAST_MAC,
    cast_mac_general = C.CKM_CAST_MAC_GENERAL,
    cast_cbc_pad = C.CKM_CAST_CBC_PAD,
    cast3_key_gen = C.CKM_CAST3_KEY_GEN,
    cast3_ecb = C.CKM_CAST3_ECB,
    cast3_cbc = C.CKM_CAST3_CBC,
    cast3_mac = C.CKM_CAST3_MAC,
    cast3_mac_general = C.CKM_CAST3_MAC_GENERAL,
    cast3_cbc_pad = C.CKM_CAST3_CBC_PAD,
    // removed CAST5 mechanisms since CAST5 == CAST-128 and values collided.
    cast128_key_gen = C.CKM_CAST128_KEY_GEN,
    cast128_ecb = C.CKM_CAST128_ECB,
    cast128_cbc = C.CKM_CAST128_CBC,
    cast128_mac = C.CKM_CAST128_MAC,
    cast128_mac_general = C.CKM_CAST128_MAC_GENERAL,
    cast128_cbc_pad = C.CKM_CAST128_CBC_PAD,
    rc5_key_gen = C.CKM_RC5_KEY_GEN,
    rc5_ecb = C.CKM_RC5_ECB,
    rc5_cbc = C.CKM_RC5_CBC,
    rc5_mac = C.CKM_RC5_MAC,
    rc5_mac_general = C.CKM_RC5_MAC_GENERAL,
    rc5_cbc_pad = C.CKM_RC5_CBC_PAD,
    idea_key_gen = C.CKM_IDEA_KEY_GEN,
    idea_ecb = C.CKM_IDEA_ECB,
    idea_cbc = C.CKM_IDEA_CBC,
    idea_mac = C.CKM_IDEA_MAC,
    idea_mac_general = C.CKM_IDEA_MAC_GENERAL,
    idea_cbc_pad = C.CKM_IDEA_CBC_PAD,
    generic_secret_key_gen = C.CKM_GENERIC_SECRET_KEY_GEN,
    concatenate_base_and_key = C.CKM_CONCATENATE_BASE_AND_KEY,
    concatenate_base_and_data = C.CKM_CONCATENATE_BASE_AND_DATA,
    concatenate_data_and_base = C.CKM_CONCATENATE_DATA_AND_BASE,
    xor_base_and_data = C.CKM_XOR_BASE_AND_DATA,
    extract_key_from_key = C.CKM_EXTRACT_KEY_FROM_KEY,
    ssl3_pre_master_key_gen = C.CKM_SSL3_PRE_MASTER_KEY_GEN,
    ssl3_master_key_derive = C.CKM_SSL3_MASTER_KEY_DERIVE,
    ssl3_key_and_mac_derive = C.CKM_SSL3_KEY_AND_MAC_DERIVE,
    ssl3_master_key_derive_dh = C.CKM_SSL3_MASTER_KEY_DERIVE_DH,
    tls_pre_master_key_gen = C.CKM_TLS_PRE_MASTER_KEY_GEN,
    tls_master_key_derive = C.CKM_TLS_MASTER_KEY_DERIVE,
    tls_key_and_mac_derive = C.CKM_TLS_KEY_AND_MAC_DERIVE,
    tls_master_key_derive_dh = C.CKM_TLS_MASTER_KEY_DERIVE_DH,
    tls_prf = C.CKM_TLS_PRF,
    ssl3_md5_mac = C.CKM_SSL3_MD5_MAC,
    ssl3_sha1_mac = C.CKM_SSL3_SHA1_MAC,
    md5_key_derivation = C.CKM_MD5_KEY_DERIVATION,
    md2_key_derivation = C.CKM_MD2_KEY_DERIVATION,
    sha1_key_derivation = C.CKM_SHA1_KEY_DERIVATION,
    sha256_key_derivation = C.CKM_SHA256_KEY_DERIVATION,
    sha384_key_derivation = C.CKM_SHA384_KEY_DERIVATION,
    sha512_key_derivation = C.CKM_SHA512_KEY_DERIVATION,
    pbe_md2_des_cbc = C.CKM_PBE_MD2_DES_CBC,
    pbe_md5_des_cbc = C.CKM_PBE_MD5_DES_CBC,
    pbe_md5_cast_cbc = C.CKM_PBE_MD5_CAST_CBC,
    pbe_md5_cast3_cbc = C.CKM_PBE_MD5_CAST3_CBC,
    // again removing CAST5, see above.
    pbe_md5_cast128_cbc = C.CKM_PBE_MD5_CAST128_CBC,
    pbe_sha1_cast128_cbc = C.CKM_PBE_SHA1_CAST128_CBC,
    pbe_sha1_rc4_128 = C.CKM_PBE_SHA1_RC4_128,
    pbe_sha1_rc4_40 = C.CKM_PBE_SHA1_RC4_40,
    pbe_sha1_des3_ede_cbc = C.CKM_PBE_SHA1_DES3_EDE_CBC,
    pbe_sha1_des2_ede_cbc = C.CKM_PBE_SHA1_DES2_EDE_CBC,
    pbe_sha1_rc2_128_cbc = C.CKM_PBE_SHA1_RC2_128_CBC,
    pbe_sha1_rc2_40_cbc = C.CKM_PBE_SHA1_RC2_40_CBC,
    pkcs5_pbkd2 = C.CKM_PKCS5_PBKD2,
    pba_sha1_with_sha1_hmac = C.CKM_PBA_SHA1_WITH_SHA1_HMAC,
    wtls_pre_master_key_gen = C.CKM_WTLS_PRE_MASTER_KEY_GEN,
    wtls_master_key_derive = C.CKM_WTLS_MASTER_KEY_DERIVE,
    wtls_master_key_derive_dh_ecc = C.CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC,
    wtls_prf = C.CKM_WTLS_PRF,
    wtls_server_key_and_mac_derive = C.CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE,
    wtls_client_key_and_mac_derive = C.CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE,
    tls10_mac_server = C.CKM_TLS10_MAC_SERVER,
    tls10_mac_client = C.CKM_TLS10_MAC_CLIENT,
    tls12_mac = C.CKM_TLS12_MAC,
    tls12_kdf = C.CKM_TLS12_KDF,
    tls12_master_key_derive = C.CKM_TLS12_MASTER_KEY_DERIVE,
    tls12_key_and_mac_derive = C.CKM_TLS12_KEY_AND_MAC_DERIVE,
    tls12_master_key_derive_dh = C.CKM_TLS12_MASTER_KEY_DERIVE_DH,
    tls12_key_safe_derive = C.CKM_TLS12_KEY_SAFE_DERIVE,
    tls_mac = C.CKM_TLS_MAC,
    tls_kdf = C.CKM_TLS_KDF,
    key_wrap_lynks = C.CKM_KEY_WRAP_LYNKS,
    key_wrap_set_oaep = C.CKM_KEY_WRAP_SET_OAEP,
    cms_sig = C.CKM_CMS_SIG,
    kip_derive = C.CKM_KIP_DERIVE,
    kip_wrap = C.CKM_KIP_WRAP,
    kip_mac = C.CKM_KIP_MAC,
    aria_key_gen = C.CKM_ARIA_KEY_GEN,
    aria_ecb = C.CKM_ARIA_ECB,
    aria_cbc = C.CKM_ARIA_CBC,
    aria_mac = C.CKM_ARIA_MAC,
    aria_mac_general = C.CKM_ARIA_MAC_GENERAL,
    aria_cbc_pad = C.CKM_ARIA_CBC_PAD,
    aria_ecb_encrypt_data = C.CKM_ARIA_ECB_ENCRYPT_DATA,
    aria_cbc_encrypt_data = C.CKM_ARIA_CBC_ENCRYPT_DATA,
    seed_key_gen = C.CKM_SEED_KEY_GEN,
    seed_ecb = C.CKM_SEED_ECB,
    seed_cbc = C.CKM_SEED_CBC,
    seed_mac = C.CKM_SEED_MAC,
    seed_mac_general = C.CKM_SEED_MAC_GENERAL,
    seed_cbc_pad = C.CKM_SEED_CBC_PAD,
    seed_ecb_encrypt_data = C.CKM_SEED_ECB_ENCRYPT_DATA,
    seed_cbc_encrypt_data = C.CKM_SEED_CBC_ENCRYPT_DATA,
    skipjack_key_gen = C.CKM_SKIPJACK_KEY_GEN,
    skipjack_ecb64 = C.CKM_SKIPJACK_ECB64,
    skipjack_cbc64 = C.CKM_SKIPJACK_CBC64,
    skipjack_ofb64 = C.CKM_SKIPJACK_OFB64,
    skipjack_cfb64 = C.CKM_SKIPJACK_CFB64,
    skipjack_cfb32 = C.CKM_SKIPJACK_CFB32,
    skipjack_cfb16 = C.CKM_SKIPJACK_CFB16,
    skipjack_cfb8 = C.CKM_SKIPJACK_CFB8,
    skipjack_wrap = C.CKM_SKIPJACK_WRAP,
    skipjack_private_wrap = C.CKM_SKIPJACK_PRIVATE_WRAP,
    skipjack_relayx = C.CKM_SKIPJACK_RELAYX,
    kea_key_pair_gen = C.CKM_KEA_KEY_PAIR_GEN,
    kea_key_derive = C.CKM_KEA_KEY_DERIVE,
    fortezza_timestamp = C.CKM_FORTEZZA_TIMESTAMP,
    baton_key_gen = C.CKM_BATON_KEY_GEN,
    baton_ecb128 = C.CKM_BATON_ECB128,
    baton_ecb96 = C.CKM_BATON_ECB96,
    baton_cbc128 = C.CKM_BATON_CBC128,
    baton_counter = C.CKM_BATON_COUNTER,
    baton_shuffle = C.CKM_BATON_SHUFFLE,
    baton_wrap = C.CKM_BATON_WRAP,
    // remove ECDSA_KEY_PAIR_GEN because it's deprecated and collides with EC_KEY_PAIR_GEN.
    ec_key_pair_gen = C.CKM_EC_KEY_PAIR_GEN,
    ecdsa = C.CKM_ECDSA,
    ecdsa_sha1 = C.CKM_ECDSA_SHA1,
    ecdsa_sha224 = C.CKM_ECDSA_SHA224,
    ecdsa_sha256 = C.CKM_ECDSA_SHA256,
    ecdsa_sha384 = C.CKM_ECDSA_SHA384,
    ecdsa_sha512 = C.CKM_ECDSA_SHA512,
    ecdh1_derive = C.CKM_ECDH1_DERIVE,
    ecdh1_cofactor_derive = C.CKM_ECDH1_COFACTOR_DERIVE,
    ecmqv_derive = C.CKM_ECMQV_DERIVE,
    ecdh_aes_key_wrap = C.CKM_ECDH_AES_KEY_WRAP,
    rsa_aes_key_wrap = C.CKM_RSA_AES_KEY_WRAP,
    juniper_key_gen = C.CKM_JUNIPER_KEY_GEN,
    juniper_ecb128 = C.CKM_JUNIPER_ECB128,
    juniper_cbc128 = C.CKM_JUNIPER_CBC128,
    juniper_counter = C.CKM_JUNIPER_COUNTER,
    juniper_shuffle = C.CKM_JUNIPER_SHUFFLE,
    juniper_wrap = C.CKM_JUNIPER_WRAP,
    fasthash = C.CKM_FASTHASH,
    aes_key_gen = C.CKM_AES_KEY_GEN,
    aes_ecb = C.CKM_AES_ECB,
    aes_cbc = C.CKM_AES_CBC,
    aes_mac = C.CKM_AES_MAC,
    aes_mac_general = C.CKM_AES_MAC_GENERAL,
    aes_cbc_pad = C.CKM_AES_CBC_PAD,
    aes_ctr = C.CKM_AES_CTR,
    aes_gcm = C.CKM_AES_GCM,
    aes_ccm = C.CKM_AES_CCM,
    aes_cts = C.CKM_AES_CTS,
    aes_cmac = C.CKM_AES_CMAC,
    aes_cmac_general = C.CKM_AES_CMAC_GENERAL,
    aes_xcbc_mac = C.CKM_AES_XCBC_MAC,
    aes_xcbc_mac_96 = C.CKM_AES_XCBC_MAC_96,
    aes_gmac = C.CKM_AES_GMAC,
    blowfish_key_gen = C.CKM_BLOWFISH_KEY_GEN,
    blowfish_cbc = C.CKM_BLOWFISH_CBC,
    twofish_key_gen = C.CKM_TWOFISH_KEY_GEN,
    twofish_cbc = C.CKM_TWOFISH_CBC,
    blowfish_cbc_pad = C.CKM_BLOWFISH_CBC_PAD,
    twofish_cbc_pad = C.CKM_TWOFISH_CBC_PAD,
    des_ecb_encrypt_data = C.CKM_DES_ECB_ENCRYPT_DATA,
    des_cbc_encrypt_data = C.CKM_DES_CBC_ENCRYPT_DATA,
    des3_ecb_encrypt_data = C.CKM_DES3_ECB_ENCRYPT_DATA,
    des3_cbc_encrypt_data = C.CKM_DES3_CBC_ENCRYPT_DATA,
    aes_ecb_encrypt_data = C.CKM_AES_ECB_ENCRYPT_DATA,
    aes_cbc_encrypt_data = C.CKM_AES_CBC_ENCRYPT_DATA,
    gostr3410_key_pair_gen = C.CKM_GOSTR3410_KEY_PAIR_GEN,
    gostr3410 = C.CKM_GOSTR3410,
    gostr3410_with_gostr3411 = C.CKM_GOSTR3410_WITH_GOSTR3411,
    gostr3410_key_wrap = C.CKM_GOSTR3410_KEY_WRAP,
    gostr3410_derive = C.CKM_GOSTR3410_DERIVE,
    gostr3411 = C.CKM_GOSTR3411,
    gostr3411_hmac = C.CKM_GOSTR3411_HMAC,
    gost28147_key_gen = C.CKM_GOST28147_KEY_GEN,
    gost28147_ecb = C.CKM_GOST28147_ECB,
    gost28147 = C.CKM_GOST28147,
    gost28147_mac = C.CKM_GOST28147_MAC,
    gost28147_key_wrap = C.CKM_GOST28147_KEY_WRAP,
    chacha20_key_gen = C.CKM_CHACHA20_KEY_GEN,
    chacha20 = C.CKM_CHACHA20,
    poly1305_key_gen = C.CKM_POLY1305_KEY_GEN,
    poly1305 = C.CKM_POLY1305,
    dsa_parameter_gen = C.CKM_DSA_PARAMETER_GEN,
    dh_pkcs_parameter_gen = C.CKM_DH_PKCS_PARAMETER_GEN,
    x9_42_dh_parameter_gen = C.CKM_X9_42_DH_PARAMETER_GEN,
    dsa_probablistic_parameter_gen = C.CKM_DSA_PROBABLISTIC_PARAMETER_GEN,
    dsa_shawe_taylor_parameter_gen = C.CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN,
    aes_ofb = C.CKM_AES_OFB,
    aes_cfb64 = C.CKM_AES_CFB64,
    aes_cfb8 = C.CKM_AES_CFB8,
    aes_cfb128 = C.CKM_AES_CFB128,
    aes_cfb1 = C.CKM_AES_CFB1,
    vendor_defined = C.CKM_VENDOR_DEFINED,
    sha224 = C.CKM_SHA224,
    sha224_hmac = C.CKM_SHA224_HMAC,
    sha224_hmac_general = C.CKM_SHA224_HMAC_GENERAL,
    sha224_rsa_pkcs = C.CKM_SHA224_RSA_PKCS,
    sha224_rsa_pkcs_pss = C.CKM_SHA224_RSA_PKCS_PSS,
    sha224_key_derivation = C.CKM_SHA224_KEY_DERIVATION,
    camellia_key_gen = C.CKM_CAMELLIA_KEY_GEN,
    camellia_ecb = C.CKM_CAMELLIA_ECB,
    camellia_cbc = C.CKM_CAMELLIA_CBC,
    camellia_mac = C.CKM_CAMELLIA_MAC,
    camellia_mac_general = C.CKM_CAMELLIA_MAC_GENERAL,
    camellia_cbc_pad = C.CKM_CAMELLIA_CBC_PAD,
    camellia_ecb_encrypt_data = C.CKM_CAMELLIA_ECB_ENCRYPT_DATA,
    camellia_cbc_encrypt_data = C.CKM_CAMELLIA_CBC_ENCRYPT_DATA,
    camellia_ctr = C.CKM_CAMELLIA_CTR,
    aes_key_wrap = C.CKM_AES_KEY_WRAP,
    aes_key_wrap_pad = C.CKM_AES_KEY_WRAP_PAD,
    rsa_pkcs_tpm_1_1 = C.CKM_RSA_PKCS_TPM_1_1,
    rsa_pkcs_oaep_tpm_1_1 = C.CKM_RSA_PKCS_OAEP_TPM_1_1,
    // backported PKCS#11 3.0 mechanisms.
    ec_edwards_key_pair_gen = C.CKM_EC_EDWARDS_KEY_PAIR_GEN,
    ec_montgomery_key_pair_gen = C.CKM_EC_MONTGOMERY_KEY_PAIR_GEN,
    eddsa = C.CKM_EDDSA,
    xeddsa = C.CKM_XEDDSA,
};

pub const Module = struct {
    ctx: *Context,
    allocator: Allocator,

    /// Caller must deinit() to close the library and free memory.
    pub fn init(alloc: Allocator, path: []const u8) !Module {
        var lib = try std.DynLib.open(path);

        const context = try alloc.create(Context);
        errdefer alloc.destroy(context);
        context.lib = lib;

        const getFunctionList = lib.lookup(C.CK_C_GetFunctionList, "C_GetFunctionList").?.?;
        const rv = getFunctionList(@ptrCast(&context.sym));
        try helpers.returnIfError(rv);

        return .{ .allocator = alloc, .ctx = context };
    }

    pub fn deinit(self: *Module) void {
        self.ctx.lib.close();
        self.allocator.destroy(self.ctx);
        self.* = undefined;
    }

    pub fn initialize(self: Module) Error!void {
        var args: C.CK_C_INITIALIZE_ARGS = .{ .flags = C.CKF_OS_LOCKING_OK };
        const rv = self.ctx.sym.C_Initialize.?(&args);
        try helpers.returnIfError(rv);
    }

    pub fn finalize(self: Module) Error!void {
        const args: C.CK_VOID_PTR = null;
        const rv = self.ctx.sym.C_Finalize.?(args);
        try helpers.returnIfError(rv);
    }

    pub fn getInfo(self: Module) Error!Info {
        var info: C.CK_INFO = undefined;
        const rv = self.ctx.sym.C_GetInfo.?(&info);
        try helpers.returnIfError(rv);

        return Info.fromCType(info);
    }

    /// Caller owns returned memory.
    pub fn getSlotList(self: Module, alloc: Allocator, token_present: bool) Error![]c_ulong {
        const present: C.CK_BBOOL = if (token_present) C.CK_TRUE else C.CK_FALSE;
        var slot_count: C.CK_ULONG = undefined;

        var rv = self.ctx.sym.C_GetSlotList.?(present, null, &slot_count);
        try helpers.returnIfError(rv);

        const slot_list = try alloc.alloc(C.CK_ULONG, slot_count);
        errdefer alloc.free(slot_list);

        rv = self.ctx.sym.C_GetSlotList.?(present, slot_list.ptr, &slot_count);
        try helpers.returnIfError(rv);

        return slot_list;
    }

    pub fn getSlotInfo(self: Module, slot_id: c_ulong) Error!SlotInfo {
        var slot_info: C.CK_SLOT_INFO = undefined;
        const rv = self.ctx.sym.C_GetSlotInfo.?(slot_id, &slot_info);
        try helpers.returnIfError(rv);

        return SlotInfo.fromCType(slot_info);
    }

    pub fn getTokenInfo(self: Module, slot_id: c_ulong) Error!TokenInfo {
        var token_info: C.CK_TOKEN_INFO = undefined;
        const rv = self.ctx.sym.C_GetTokenInfo.?(slot_id, &token_info);
        try helpers.returnIfError(rv);

        return TokenInfo.fromCType(token_info);
    }

    /// Caller owns returned memory.
    pub fn getMechanismList(self: Module, alloc: Allocator, slot_id: c_ulong) Error![]MechanismType {
        var mech_count: C.CK_ULONG = undefined;

        var rv = self.ctx.sym.C_GetMechanismList.?(slot_id, null, &mech_count);
        try helpers.returnIfError(rv);

        const mech_list = try alloc.alloc(MechanismType, mech_count);
        errdefer alloc.free(mech_list);

        rv = self.ctx.sym.C_GetMechanismList.?(slot_id, @ptrCast(mech_list.ptr), &mech_count);
        try helpers.returnIfError(rv);

        return mech_list;
    }

    pub fn getMechanismInfo(self: Module, slot_id: c_ulong, mech_type: MechanismType) Error!MechanismInfo {
        var mech_info: C.CK_MECHANISM_INFO = undefined;
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
        var c_flags: c_ulong = 0;

        if (flags.read_write) {
            c_flags = c_flags | C.CKF_RW_SESSION;
        }
        if (flags.serial) {
            c_flags = c_flags | C.CKF_SERIAL_SESSION;
        }

        var handle: C.CK_SESSION_HANDLE = 0;

        // We're *NOT* supporting Notify/Callback setups here on purpose.
        const rv = self.ctx.sym.C_OpenSession.?(slot_id, c_flags, null, null, &handle);
        try helpers.returnIfError(rv);

        return .{ .handle = handle, .ctx = self.ctx };
    }

    pub fn closeAllSessions(self: Module, slot_id: c_ulong) Error!void {
        const rv = self.ctx.sym.C_CloseAllSessions.?(slot_id);
        try helpers.returnIfError(rv);
    }
};
