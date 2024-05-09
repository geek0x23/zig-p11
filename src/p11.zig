const std = @import("std");
const builtin = @import("builtin");
const config = @import("config");
const c = @cImport({
    @cInclude("cryptoki.h");
});

const Allocator = std.mem.Allocator;
const testing = std.testing;

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

pub const MechanismType = enum(c_ulong) {
    rsa_pkcs_key_pair_gen = c.CKM_RSA_PKCS_KEY_PAIR_GEN,
    rsa_pkcs = c.CKM_RSA_PKCS,
    rsa_9796 = c.CKM_RSA_9796,
    rsa_x509 = c.CKM_RSA_X_509,
    md2_rsa_pkcs = c.CKM_MD2_RSA_PKCS,
    md5_rsa_pkcs = c.CKM_MD5_RSA_PKCS,
    sha1_rsa_pkcs = c.CKM_SHA1_RSA_PKCS,
    ripemd128_rsa_pkcs = c.CKM_RIPEMD128_RSA_PKCS,
    ripemd160_rsa_pkcs = c.CKM_RIPEMD160_RSA_PKCS,
    rsa_pkcs_oaep = c.CKM_RSA_PKCS_OAEP,
    rsa_x9_31_key_pair_gen = c.CKM_RSA_X9_31_KEY_PAIR_GEN,
    rsa_x9_31 = c.CKM_RSA_X9_31,
    sha1_rsa_x9_31 = c.CKM_SHA1_RSA_X9_31,
    rsa_pkcs_pss = c.CKM_RSA_PKCS_PSS,
    sha1_rsa_pkcs_pss = c.CKM_SHA1_RSA_PKCS_PSS,
    dsa_key_pair_gen = c.CKM_DSA_KEY_PAIR_GEN,
    dsa = c.CKM_DSA,
    dsa_sha1 = c.CKM_DSA_SHA1,
    dsa_sha224 = c.CKM_DSA_SHA224,
    dsa_sha256 = c.CKM_DSA_SHA256,
    dsa_sha384 = c.CKM_DSA_SHA384,
    dsa_sha512 = c.CKM_DSA_SHA512,
    dh_pkcs_key_pair_gen = c.CKM_DH_PKCS_KEY_PAIR_GEN,
    dh_pkcs_derive = c.CKM_DH_PKCS_DERIVE,
    x9_42_dh_key_pair_gen = c.CKM_X9_42_DH_KEY_PAIR_GEN,
    x9_42_dh_derive = c.CKM_X9_42_DH_DERIVE,
    x9_42_dh_hybrid_derive = c.CKM_X9_42_DH_HYBRID_DERIVE,
    x9_42_mqv_derive = c.CKM_X9_42_MQV_DERIVE,
    sha256_rsa_pkcs = c.CKM_SHA256_RSA_PKCS,
    sha384_rsa_pkcs = c.CKM_SHA384_RSA_PKCS,
    sha512_rsa_pkcs = c.CKM_SHA512_RSA_PKCS,
    sha256_rsa_pkcs_pss = c.CKM_SHA256_RSA_PKCS_PSS,
    sha384_rsa_pkcs_pss = c.CKM_SHA384_RSA_PKCS_PSS,
    sha512_rsa_pkcs_pss = c.CKM_SHA512_RSA_PKCS_PSS,
    sha224_rsa_pkcs = c.CKM_SHA224_RSA_PKCS,
    sha224_rsa_pkcs_pss = c.CKM_SHA224_RSA_PKCS_PSS,
    sha512_224 = c.CKM_SHA512_224,
    sha512_224_hmac = c.CKM_SHA512_224_HMAC,
    sha512_224_hmac_general = c.CKM_SHA512_224_HMAC_GENERAL,
    sha512_224_key_derivation = c.CKM_SHA512_224_KEY_DERIVATION,
    sha512_256 = c.CKM_SHA512_256,
    sha512_256_hmac = c.CKM_SHA512_256_HMAC,
    sha512_256_hmac_general = c.CKM_SHA512_256_HMAC_GENERAL,
    sha512_256_key_derivation = c.CKM_SHA512_256_KEY_DERIVATION,
    sha512_t = c.CKM_SHA512_T,
    sha512_t_hmac = c.CKM_SHA512_T_HMAC,
    sha512_t_hmac_general = c.CKM_SHA512_T_HMAC_GENERAL,
    sha512_t_key_derivation = c.CKM_SHA512_T_KEY_DERIVATION,
    rc2_key_gen = c.CKM_RC2_KEY_GEN,
    rc2_ecb = c.CKM_RC2_ECB,
    rc2_cbc = c.CKM_RC2_CBC,
    rc2_mac = c.CKM_RC2_MAC,
    rc2_mac_general = c.CKM_RC2_MAC_GENERAL,
    rc2_cbc_pad = c.CKM_RC2_CBC_PAD,
    rc4_key_gen = c.CKM_RC4_KEY_GEN,
    rc4 = c.CKM_RC4,
    des_key_gen = c.CKM_DES_KEY_GEN,
    des_ecb = c.CKM_DES_ECB,
    des_cbc = c.CKM_DES_CBC,
    des_mac = c.CKM_DES_MAC,
    des_mac_general = c.CKM_DES_MAC_GENERAL,
    des_cbc_pad = c.CKM_DES_CBC_PAD,
    des2_key_gen = c.CKM_DES2_KEY_GEN,
    des3_key_gen = c.CKM_DES3_KEY_GEN,
    des3_ecb = c.CKM_DES3_ECB,
    des3_cbc = c.CKM_DES3_CBC,
    des3_mac = c.CKM_DES3_MAC,
    des3_mac_general = c.CKM_DES3_MAC_GENERAL,
    des3_cbc_pad = c.CKM_DES3_CBC_PAD,
    des3_cmac_general = c.CKM_DES3_CMAC_GENERAL,
    des3_cmac = c.CKM_DES3_CMAC,
    cdmf_key_gen = c.CKM_CDMF_KEY_GEN,
    cdmf_ecb = c.CKM_CDMF_ECB,
    cdmf_cbc = c.CKM_CDMF_CBC,
    cdmf_mac = c.CKM_CDMF_MAC,
    cdmf_mac_general = c.CKM_CDMF_MAC_GENERAL,
    cdmf_cbc_pad = c.CKM_CDMF_CBC_PAD,
    des_ofb64 = c.CKM_DES_OFB64,
    des_ofb8 = c.CKM_DES_OFB8,
    des_cfb64 = c.CKM_DES_CFB64,
    des_cfb8 = c.CKM_DES_CFB8,
    md2 = c.CKM_MD2,
    md2_hmac = c.CKM_MD2_HMAC,
    md2_hmac_general = c.CKM_MD2_HMAC_GENERAL,
    md5 = c.CKM_MD5,
    md5_hmac = c.CKM_MD5_HMAC,
    md5_hmac_general = c.CKM_MD5_HMAC_GENERAL,
    sha_1 = c.CKM_SHA_1,
    sha_1_hmac = c.CKM_SHA_1_HMAC,
    sha_1_hmac_general = c.CKM_SHA_1_HMAC_GENERAL,
    ripemd128 = c.CKM_RIPEMD128,
    ripemd128_hmac = c.CKM_RIPEMD128_HMAC,
    ripemd128_hmac_general = c.CKM_RIPEMD128_HMAC_GENERAL,
    ripemd160 = c.CKM_RIPEMD160,
    ripemd160_hmac = c.CKM_RIPEMD160_HMAC,
    ripemd160_hmac_general = c.CKM_RIPEMD160_HMAC_GENERAL,
    sha256 = c.CKM_SHA256,
    sha256_hmac = c.CKM_SHA256_HMAC,
    sha256_hmac_general = c.CKM_SHA256_HMAC_GENERAL,
    sha224 = c.CKM_SHA224,
    sha224_hmac = c.CKM_SHA224_HMAC,
    sha224_hmac_general = c.CKM_SHA224_HMAC_GENERAL,
    sha384 = c.CKM_SHA384,
    sha384_hmac = c.CKM_SHA384_HMAC,
    sha384_hmac_general = c.CKM_SHA384_HMAC_GENERAL,
    sha512 = c.CKM_SHA512,
    sha512_hmac = c.CKM_SHA512_HMAC,
    sha512_hmac_general = c.CKM_SHA512_HMAC_GENERAL,
    securid_key_gen = c.CKM_SECURID_KEY_GEN,
    securid = c.CKM_SECURID,
    hotp_key_gen = c.CKM_HOTP_KEY_GEN,
    hotp = c.CKM_HOTP,
    acti = c.CKM_ACTI,
    acti_key_gen = c.CKM_ACTI_KEY_GEN,
    cast_key_gen = c.CKM_CAST_KEY_GEN,
    cast_ecb = c.CKM_CAST_ECB,
    cast_cbc = c.CKM_CAST_CBC,
    cast_mac = c.CKM_CAST_MAC,
    cast_mac_general = c.CKM_CAST_MAC_GENERAL,
    cast_cbc_pad = c.CKM_CAST_CBC_PAD,
    cast3_key_gen = c.CKM_CAST3_KEY_GEN,
    cast3_ecb = c.CKM_CAST3_ECB,
    cast3_cbc = c.CKM_CAST3_CBC,
    cast3_mac = c.CKM_CAST3_MAC,
    cast3_mac_general = c.CKM_CAST3_MAC_GENERAL,
    cast3_cbc_pad = c.CKM_CAST3_CBC_PAD,
    // CAST5 mechanisms omitted intentionally, since CAST-128 is the same thing.
    cast128_key_gen = c.CKM_CAST128_KEY_GEN,
    cast128_ecb = c.CKM_CAST128_ECB,
    cast128_cbc = c.CKM_CAST128_CBC,
    cast128_mac = c.CKM_CAST128_MAC,
    cast128_mac_general = c.CKM_CAST128_MAC_GENERAL,
    cast128_cbc_pad = c.CKM_CAST128_CBC_PAD,
    rc5_key_gen = c.CKM_RC5_KEY_GEN,
    rc5_ecb = c.CKM_RC5_ECB,
    rc5_cbc = c.CKM_RC5_CBC,
    rc5_mac = c.CKM_RC5_MAC,
    rc5_mac_general = c.CKM_RC5_MAC_GENERAL,
    rc5_cbc_pad = c.CKM_RC5_CBC_PAD,
    idea_key_gen = c.CKM_IDEA_KEY_GEN,
    idea_ecb = c.CKM_IDEA_ECB,
    idea_cbc = c.CKM_IDEA_CBC,
    idea_mac = c.CKM_IDEA_MAC,
    idea_mac_general = c.CKM_IDEA_MAC_GENERAL,
    idea_cbc_pad = c.CKM_IDEA_CBC_PAD,
    generic_secret_key_gen = c.CKM_GENERIC_SECRET_KEY_GEN,
    concatenate_base_and_key = c.CKM_CONCATENATE_BASE_AND_KEY,
    concatenate_base_and_data = c.CKM_CONCATENATE_BASE_AND_DATA,
    concatenate_data_and_base = c.CKM_CONCATENATE_DATA_AND_BASE,
    xor_base_and_data = c.CKM_XOR_BASE_AND_DATA,
    extract_key_from_key = c.CKM_EXTRACT_KEY_FROM_KEY,
    ssl3_pre_master_key_gen = c.CKM_SSL3_PRE_MASTER_KEY_GEN,
    ssl3_master_key_derive = c.CKM_SSL3_MASTER_KEY_DERIVE,
    ssl3_key_and_mac_derive = c.CKM_SSL3_KEY_AND_MAC_DERIVE,
    ssl3_master_key_derive_dh = c.CKM_SSL3_MASTER_KEY_DERIVE_DH,
    tls_pre_master_key_gen = c.CKM_TLS_PRE_MASTER_KEY_GEN,
    tls_master_key_derive = c.CKM_TLS_MASTER_KEY_DERIVE,
    tls_key_and_mac_derive = c.CKM_TLS_KEY_AND_MAC_DERIVE,
    tls_master_key_derive_dh = c.CKM_TLS_MASTER_KEY_DERIVE_DH,
    tls_prf = c.CKM_TLS_PRF,
    ssl3_md5_mac = c.CKM_SSL3_MD5_MAC,
    ssl3_sha1_mac = c.CKM_SSL3_SHA1_MAC,
    md5_key_derivation = c.CKM_MD5_KEY_DERIVATION,
    md2_key_derivation = c.CKM_MD2_KEY_DERIVATION,
    sha1_key_derivation = c.CKM_SHA1_KEY_DERIVATION,
    sha256_key_derivation = c.CKM_SHA256_KEY_DERIVATION,
    sha384_key_derivation = c.CKM_SHA384_KEY_DERIVATION,
    sha512_key_derivation = c.CKM_SHA512_KEY_DERIVATION,
    sha224_key_derivation = c.CKM_SHA224_KEY_DERIVATION,
    pbe_md2_des_cbc = c.CKM_PBE_MD2_DES_CBC,
    pbe_md5_des_cbc = c.CKM_PBE_MD5_DES_CBC,
    pbe_md5_cast_cbc = c.CKM_PBE_MD5_CAST_CBC,
    pbe_md5_cast3_cbc = c.CKM_PBE_MD5_CAST3_CBC,
    // CAST5 mechanisms omitted intentionally, since CAST-128 is the same thing.
    pbe_md5_cast128_cbc = c.CKM_PBE_MD5_CAST128_CBC,
    pbe_sha1_cast128_cbc = c.CKM_PBE_SHA1_CAST128_CBC,
    pbe_sha1_rc4_128 = c.CKM_PBE_SHA1_RC4_128,
    pbe_sha1_rc4_40 = c.CKM_PBE_SHA1_RC4_40,
    pbe_sha1_des3_ede_cbc = c.CKM_PBE_SHA1_DES3_EDE_CBC,
    pbe_sha1_des2_ede_cbc = c.CKM_PBE_SHA1_DES2_EDE_CBC,
    pbe_sha1_rc2_128_cbc = c.CKM_PBE_SHA1_RC2_128_CBC,
    pbe_sha1_rc2_40_cbc = c.CKM_PBE_SHA1_RC2_40_CBC,
    pkcs5_pbkd2 = c.CKM_PKCS5_PBKD2,
    pba_sha1_with_sha1_hmac = c.CKM_PBA_SHA1_WITH_SHA1_HMAC,
    wtls_pre_master_key_gen = c.CKM_WTLS_PRE_MASTER_KEY_GEN,
    wtls_master_key_derive = c.CKM_WTLS_MASTER_KEY_DERIVE,
    wtls_master_key_derive_dh_ecc = c.CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC,
    wtls_prf = c.CKM_WTLS_PRF,
    wtls_server_key_and_mac_derive = c.CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE,
    wtls_client_key_and_mac_derive = c.CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE,
    tls10_mac_server = c.CKM_TLS10_MAC_SERVER,
    tls10_mac_client = c.CKM_TLS10_MAC_CLIENT,
    tls12_mac = c.CKM_TLS12_MAC,
    tls12_kdf = c.CKM_TLS12_KDF,
    tls12_master_key_derive = c.CKM_TLS12_MASTER_KEY_DERIVE,
    tls12_key_and_mac_derive = c.CKM_TLS12_KEY_AND_MAC_DERIVE,
    tls12_master_key_derive_dh = c.CKM_TLS12_MASTER_KEY_DERIVE_DH,
    tls12_key_safe_derive = c.CKM_TLS12_KEY_SAFE_DERIVE,
    tls_mac = c.CKM_TLS_MAC,
    tls_kdf = c.CKM_TLS_KDF,
    key_wrap_lynks = c.CKM_KEY_WRAP_LYNKS,
    key_wrap_set_oaep = c.CKM_KEY_WRAP_SET_OAEP,
    cms_sig = c.CKM_CMS_SIG,
    kip_derive = c.CKM_KIP_DERIVE,
    kip_wrap = c.CKM_KIP_WRAP,
    kip_mac = c.CKM_KIP_MAC,
    camellia_key_gen = c.CKM_CAMELLIA_KEY_GEN,
    camellia_ecb = c.CKM_CAMELLIA_ECB,
    camellia_cbc = c.CKM_CAMELLIA_CBC,
    camellia_mac = c.CKM_CAMELLIA_MAC,
    camellia_mac_general = c.CKM_CAMELLIA_MAC_GENERAL,
    camellia_cbc_pad = c.CKM_CAMELLIA_CBC_PAD,
    camellia_ecb_encrypt_data = c.CKM_CAMELLIA_ECB_ENCRYPT_DATA,
    camellia_cbc_encrypt_data = c.CKM_CAMELLIA_CBC_ENCRYPT_DATA,
    camellia_ctr = c.CKM_CAMELLIA_CTR,
    aria_key_gen = c.CKM_ARIA_KEY_GEN,
    aria_ecb = c.CKM_ARIA_ECB,
    aria_cbc = c.CKM_ARIA_CBC,
    aria_mac = c.CKM_ARIA_MAC,
    aria_mac_general = c.CKM_ARIA_MAC_GENERAL,
    aria_cbc_pad = c.CKM_ARIA_CBC_PAD,
    aria_ecb_encrypt_data = c.CKM_ARIA_ECB_ENCRYPT_DATA,
    aria_cbc_encrypt_data = c.CKM_ARIA_CBC_ENCRYPT_DATA,
    seed_key_gen = c.CKM_SEED_KEY_GEN,
    seed_ecb = c.CKM_SEED_ECB,
    seed_cbc = c.CKM_SEED_CBC,
    seed_mac = c.CKM_SEED_MAC,
    seed_mac_general = c.CKM_SEED_MAC_GENERAL,
    seed_cbc_pad = c.CKM_SEED_CBC_PAD,
    seed_ecb_encrypt_data = c.CKM_SEED_ECB_ENCRYPT_DATA,
    seed_cbc_encrypt_data = c.CKM_SEED_CBC_ENCRYPT_DATA,
    skipjack_key_gen = c.CKM_SKIPJACK_KEY_GEN,
    skipjack_ecb64 = c.CKM_SKIPJACK_ECB64,
    skipjack_cbc64 = c.CKM_SKIPJACK_CBC64,
    skipjack_ofb64 = c.CKM_SKIPJACK_OFB64,
    skipjack_cfb64 = c.CKM_SKIPJACK_CFB64,
    skipjack_cfb32 = c.CKM_SKIPJACK_CFB32,
    skipjack_cfb16 = c.CKM_SKIPJACK_CFB16,
    skipjack_cfb8 = c.CKM_SKIPJACK_CFB8,
    skipjack_wrap = c.CKM_SKIPJACK_WRAP,
    skipjack_private_wrap = c.CKM_SKIPJACK_PRIVATE_WRAP,
    skipjack_relayx = c.CKM_SKIPJACK_RELAYX,
    kea_key_pair_gen = c.CKM_KEA_KEY_PAIR_GEN,
    kea_key_derive = c.CKM_KEA_KEY_DERIVE,
    kea_derive = c.CKM_KEA_DERIVE,
    fortezza_timestamp = c.CKM_FORTEZZA_TIMESTAMP,
    baton_key_gen = c.CKM_BATON_KEY_GEN,
    baton_ecb128 = c.CKM_BATON_ECB128,
    baton_ecb96 = c.CKM_BATON_ECB96,
    baton_cbc128 = c.CKM_BATON_CBC128,
    baton_counter = c.CKM_BATON_COUNTER,
    baton_shuffle = c.CKM_BATON_SHUFFLE,
    baton_wrap = c.CKM_BATON_WRAP,
    // ommited ecdsa_key_pair_gen (deprecated name conflicts with ec_key_pair_gen)
    ec_key_pair_gen = c.CKM_EC_KEY_PAIR_GEN,
    ecdsa = c.CKM_ECDSA,
    ecdsa_sha1 = c.CKM_ECDSA_SHA1,
    ecdsa_sha224 = c.CKM_ECDSA_SHA224,
    ecdsa_sha256 = c.CKM_ECDSA_SHA256,
    ecdsa_sha384 = c.CKM_ECDSA_SHA384,
    ecdsa_sha512 = c.CKM_ECDSA_SHA512,
    ecdh1_derive = c.CKM_ECDH1_DERIVE,
    ecdh1_cofactor_derive = c.CKM_ECDH1_COFACTOR_DERIVE,
    ecmqv_derive = c.CKM_ECMQV_DERIVE,
    ecdh_aes_key_wrap = c.CKM_ECDH_AES_KEY_WRAP,
    rsa_aes_key_wrap = c.CKM_RSA_AES_KEY_WRAP,
    juniper_key_gen = c.CKM_JUNIPER_KEY_GEN,
    juniper_ecb128 = c.CKM_JUNIPER_ECB128,
    juniper_cbc128 = c.CKM_JUNIPER_CBC128,
    juniper_counter = c.CKM_JUNIPER_COUNTER,
    juniper_shuffle = c.CKM_JUNIPER_SHUFFLE,
    juniper_wrap = c.CKM_JUNIPER_WRAP,
    fasthash = c.CKM_FASTHASH,
    aes_key_gen = c.CKM_AES_KEY_GEN,
    aes_ecb = c.CKM_AES_ECB,
    aes_cbc = c.CKM_AES_CBC,
    aes_mac = c.CKM_AES_MAC,
    aes_mac_general = c.CKM_AES_MAC_GENERAL,
    aes_cbc_pad = c.CKM_AES_CBC_PAD,
    aes_ctr = c.CKM_AES_CTR,
    aes_gcm = c.CKM_AES_GCM,
    aes_ccm = c.CKM_AES_CCM,
    aes_cts = c.CKM_AES_CTS,
    aes_cmac = c.CKM_AES_CMAC,
    aes_cmac_general = c.CKM_AES_CMAC_GENERAL,
    aes_xcbc_mac = c.CKM_AES_XCBC_MAC,
    aes_xcbc_mac_96 = c.CKM_AES_XCBC_MAC_96,
    aes_gmac = c.CKM_AES_GMAC,
    blowfish_key_gen = c.CKM_BLOWFISH_KEY_GEN,
    blowfish_cbc = c.CKM_BLOWFISH_CBC,
    twofish_key_gen = c.CKM_TWOFISH_KEY_GEN,
    twofish_cbc = c.CKM_TWOFISH_CBC,
    blowfish_cbc_pad = c.CKM_BLOWFISH_CBC_PAD,
    twofish_cbc_pad = c.CKM_TWOFISH_CBC_PAD,
    des_ecb_encrypt_data = c.CKM_DES_ECB_ENCRYPT_DATA,
    des_cbc_encrypt_data = c.CKM_DES_CBC_ENCRYPT_DATA,
    des3_ecb_encrypt_data = c.CKM_DES3_ECB_ENCRYPT_DATA,
    des3_cbc_encrypt_data = c.CKM_DES3_CBC_ENCRYPT_DATA,
    aes_ecb_encrypt_data = c.CKM_AES_ECB_ENCRYPT_DATA,
    aes_cbc_encrypt_data = c.CKM_AES_CBC_ENCRYPT_DATA,
    gostr3410_key_pair_gen = c.CKM_GOSTR3410_KEY_PAIR_GEN,
    gostr3410 = c.CKM_GOSTR3410,
    gostr3410_with_gostr3411 = c.CKM_GOSTR3410_WITH_GOSTR3411,
    gostr3410_key_wrap = c.CKM_GOSTR3410_KEY_WRAP,
    gostr3410_derive = c.CKM_GOSTR3410_DERIVE,
    gostr3411 = c.CKM_GOSTR3411,
    gostr3411_hmac = c.CKM_GOSTR3411_HMAC,
    gost28147_key_gen = c.CKM_GOST28147_KEY_GEN,
    gost28147_ecb = c.CKM_GOST28147_ECB,
    gost28147 = c.CKM_GOST28147,
    gost28147_mac = c.CKM_GOST28147_MAC,
    gost28147_key_wrap = c.CKM_GOST28147_KEY_WRAP,
    dsa_parameter_gen = c.CKM_DSA_PARAMETER_GEN,
    dh_pkcs_parameter_gen = c.CKM_DH_PKCS_PARAMETER_GEN,
    x9_42_dh_parameter_gen = c.CKM_X9_42_DH_PARAMETER_GEN,
    dsa_probablistic_parameter_gen = c.CKM_DSA_PROBABLISTIC_PARAMETER_GEN,
    dsa_shawe_taylor_parameter_gen = c.CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN,
    aes_ofb = c.CKM_AES_OFB,
    aes_cfb64 = c.CKM_AES_CFB64,
    aes_cfb8 = c.CKM_AES_CFB8,
    aes_cfb128 = c.CKM_AES_CFB128,
    aes_cfb1 = c.CKM_AES_CFB1,
    aes_key_wrap = c.CKM_AES_KEY_WRAP,
    aes_key_wrap_pad = c.CKM_AES_KEY_WRAP_PAD,
    rsa_pkcs_tpm_1_1 = c.CKM_RSA_PKCS_TPM_1_1,
    rsa_pkcs_oaep_tpm_1_1 = c.CKM_RSA_PKCS_OAEP_TPM_1_1,
    // Some implementations of PKCS#11 back-ported v3 mechanisms to v2.40.... so we do the same to avoid panics.
    ec_edwards_key_pair_gen = 0x00001055,
    eddsa = 0x00001057,
};

pub const UserType = enum(c_ulong) {
    system_operator = c.CKU_SO,
    user = c.CKU_USER,
    context_specific = c.CKU_CONTEXT_SPECIFIC,
};

const Context = struct {
    lib: std.DynLib,
    sym: *c.CK_FUNCTION_LIST,
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

        const getFunctionList = lib.lookup(c.CK_C_GetFunctionList, "C_GetFunctionList").?.?;
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

    pub fn initialize(self: PKCS11Token) Error!void {
        var args: c.CK_C_INITIALIZE_ARGS = .{ .flags = c.CKF_OS_LOCKING_OK };
        const rv = self.ctx.sym.C_Initialize.?(&args);
        try returnIfError(rv);
    }

    pub fn finalize(self: PKCS11Token) Error!void {
        const args: c.CK_VOID_PTR = null;
        const rv = self.ctx.sym.C_Finalize.?(args);
        try returnIfError(rv);
    }

    /// Caller owns returned memory.
    pub fn getInfo(self: PKCS11Token) Error!Info {
        var info: c.CK_INFO = undefined;
        const rv = self.ctx.sym.C_GetInfo.?(&info);
        try returnIfError(rv);

        return Info.fromCType(info);
    }

    /// Caller owns returned memory.
    pub fn getSlotList(self: PKCS11Token, token_present: bool) Error![]c_ulong {
        const present: c.CK_BBOOL = if (token_present) c.CK_TRUE else c.CK_FALSE;
        var slot_count: c.CK_ULONG = undefined;

        var rv = self.ctx.sym.C_GetSlotList.?(present, null, &slot_count);
        try returnIfError(rv);

        const slot_list = try self.allocator.alloc(c.CK_ULONG, slot_count);
        rv = self.ctx.sym.C_GetSlotList.?(present, slot_list.ptr, &slot_count);
        try returnIfError(rv);

        return slot_list;
    }

    pub fn getSlotInfo(self: PKCS11Token, slot_id: c_ulong) Error!SlotInfo {
        var slot_info: c.CK_SLOT_INFO = undefined;
        const rv = self.ctx.sym.C_GetSlotInfo.?(slot_id, &slot_info);
        try returnIfError(rv);

        return SlotInfo.fromCType(slot_info);
    }

    pub fn getTokenInfo(self: PKCS11Token, slot_id: c_ulong) Error!TokenInfo {
        var token_info: c.CK_TOKEN_INFO = undefined;
        const rv = self.ctx.sym.C_GetTokenInfo.?(slot_id, &token_info);
        try returnIfError(rv);

        return TokenInfo.fromCType(token_info);
    }

    /// Caller owns returned memory.
    pub fn getMechanismList(self: PKCS11Token, slot_id: c_ulong) Error![]MechanismType {
        var mech_count: c.CK_ULONG = undefined;

        var rv = self.ctx.sym.C_GetMechanismList.?(slot_id, null, &mech_count);
        try returnIfError(rv);

        const mech_list = try self.allocator.alloc(MechanismType, mech_count);
        rv = self.ctx.sym.C_GetMechanismList.?(slot_id, @ptrCast(mech_list.ptr), &mech_count);
        try returnIfError(rv);

        return mech_list;
    }

    pub fn getMechanismInfo(self: PKCS11Token, slot_id: c_ulong, mech_type: MechanismType) Error!MechanismInfo {
        var mech_info: c.CK_MECHANISM_INFO = undefined;
        const rv = self.ctx.sym.C_GetMechanismInfo.?(slot_id, @intFromEnum(mech_type), &mech_info);
        try returnIfError(rv);

        return MechanismInfo.fromCType(mech_info);
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
    OK = c.CKR_OK,
    CANCEL = c.CKR_CANCEL,
    HOST_MEMORY = c.CKR_HOST_MEMORY,
    SLOT_ID_INVALID = c.CKR_SLOT_ID_INVALID,
    GENERAL_ERROR = c.CKR_GENERAL_ERROR,
    FUNCTION_FAILED = c.CKR_FUNCTION_FAILED,
    ARGUMENTS_BAD = c.CKR_ARGUMENTS_BAD,
    NO_EVENT = c.CKR_NO_EVENT,
    NEED_TO_CREATE_THREADS = c.CKR_NEED_TO_CREATE_THREADS,
    CANT_LOCK = c.CKR_CANT_LOCK,
    ATTRIBUTE_READ_ONLY = c.CKR_ATTRIBUTE_READ_ONLY,
    ATTRIBUTE_SENSITIVE = c.CKR_ATTRIBUTE_SENSITIVE,
    ATTRIBUTE_TYPE_INVALID = c.CKR_ATTRIBUTE_TYPE_INVALID,
    ATTRIBUTE_VALUE_INVALID = c.CKR_ATTRIBUTE_VALUE_INVALID,
    ACTION_PROHIBITED = c.CKR_ACTION_PROHIBITED,
    DATA_INVALID = c.CKR_DATA_INVALID,
    DATA_LEN_RANGE = c.CKR_DATA_LEN_RANGE,
    DEVICE_ERROR = c.CKR_DEVICE_ERROR,
    DEVICE_MEMORY = c.CKR_DEVICE_MEMORY,
    DEVICE_REMOVED = c.CKR_DEVICE_REMOVED,
    ENCRYPTED_DATA_INVALID = c.CKR_ENCRYPTED_DATA_INVALID,
    ENCRYPTED_DATA_LEN_RANGE = c.CKR_ENCRYPTED_DATA_LEN_RANGE,
    FUNCTION_CANCELED = c.CKR_FUNCTION_CANCELED,
    FUNCTION_NOT_PARALLEL = c.CKR_FUNCTION_NOT_PARALLEL,
    FUNCTION_NOT_SUPPORTED = c.CKR_FUNCTION_NOT_SUPPORTED,
    KEY_HANDLE_INVALID = c.CKR_KEY_HANDLE_INVALID,
    KEY_SIZE_RANGE = c.CKR_KEY_SIZE_RANGE,
    KEY_TYPE_INCONSISTENT = c.CKR_KEY_TYPE_INCONSISTENT,
    KEY_NOT_NEEDED = c.CKR_KEY_NOT_NEEDED,
    KEY_CHANGED = c.CKR_KEY_CHANGED,
    KEY_NEEDED = c.CKR_KEY_NEEDED,
    KEY_INDIGESTIBLE = c.CKR_KEY_INDIGESTIBLE,
    KEY_FUNCTION_NOT_PERMITTED = c.CKR_KEY_FUNCTION_NOT_PERMITTED,
    KEY_NOT_WRAPPABLE = c.CKR_KEY_NOT_WRAPPABLE,
    KEY_UNEXTRACTABLE = c.CKR_KEY_UNEXTRACTABLE,
    MECHANISM_INVALID = c.CKR_MECHANISM_INVALID,
    MECHANISM_PARAM_INVALID = c.CKR_MECHANISM_PARAM_INVALID,
    OBJECT_HANDLE_INVALID = c.CKR_OBJECT_HANDLE_INVALID,
    OPERATION_ACTIVE = c.CKR_OPERATION_ACTIVE,
    OPERATION_NOT_INITIALIZED = c.CKR_OPERATION_NOT_INITIALIZED,
    PIN_INCORRECT = c.CKR_PIN_INCORRECT,
    PIN_INVALID = c.CKR_PIN_INVALID,
    PIN_LEN_RANGE = c.CKR_PIN_LEN_RANGE,
    PIN_EXPIRED = c.CKR_PIN_EXPIRED,
    PIN_LOCKED = c.CKR_PIN_LOCKED,
    SESSION_CLOSED = c.CKR_SESSION_CLOSED,
    SESSION_COUNT = c.CKR_SESSION_COUNT,
    SESSION_HANDLE_INVALID = c.CKR_SESSION_HANDLE_INVALID,
    SESSION_PARALLEL_NOT_SUPPORTED = c.CKR_SESSION_PARALLEL_NOT_SUPPORTED,
    SESSION_READ_ONLY = c.CKR_SESSION_READ_ONLY,
    SESSION_EXISTS = c.CKR_SESSION_EXISTS,
    SESSION_READ_ONLY_EXISTS = c.CKR_SESSION_READ_ONLY_EXISTS,
    SESSION_READ_WRITE_SO_EXISTS = c.CKR_SESSION_READ_WRITE_SO_EXISTS,
    SIGNATURE_INVALID = c.CKR_SIGNATURE_INVALID,
    SIGNATURE_LEN_RANGE = c.CKR_SIGNATURE_LEN_RANGE,
    TEMPLATE_INCOMPLETE = c.CKR_TEMPLATE_INCOMPLETE,
    TEMPLATE_INCONSISTENT = c.CKR_TEMPLATE_INCONSISTENT,
    TOKEN_NOT_PRESENT = c.CKR_TOKEN_NOT_PRESENT,
    TOKEN_NOT_RECOGNIZED = c.CKR_TOKEN_NOT_RECOGNIZED,
    TOKEN_WRITE_PROTECTED = c.CKR_TOKEN_WRITE_PROTECTED,
    UNWRAPPING_KEY_HANDLE_INVALID = c.CKR_UNWRAPPING_KEY_HANDLE_INVALID,
    UNWRAPPING_KEY_SIZE_RANGE = c.CKR_UNWRAPPING_KEY_SIZE_RANGE,
    UNWRAPPING_KEY_TYPE_INCONSISTENT = c.CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT,
    USER_ALREADY_LOGGED_IN = c.CKR_USER_ALREADY_LOGGED_IN,
    USER_NOT_LOGGED_IN = c.CKR_USER_NOT_LOGGED_IN,
    USER_PIN_NOT_INITIALIZED = c.CKR_USER_PIN_NOT_INITIALIZED,
    USER_TYPE_INVALID = c.CKR_USER_TYPE_INVALID,
    USER_ANOTHER_ALREADY_LOGGED_IN = c.CKR_USER_ANOTHER_ALREADY_LOGGED_IN,
    USER_TOO_MANY_TYPES = c.CKR_USER_TOO_MANY_TYPES,
    WRAPPED_KEY_INVALID = c.CKR_WRAPPED_KEY_INVALID,
    WRAPPED_KEY_LEN_RANGE = c.CKR_WRAPPED_KEY_LEN_RANGE,
    WRAPPING_KEY_HANDLE_INVALID = c.CKR_WRAPPING_KEY_HANDLE_INVALID,
    WRAPPING_KEY_SIZE_RANGE = c.CKR_WRAPPING_KEY_SIZE_RANGE,
    WRAPPING_KEY_TYPE_INCONSISTENT = c.CKR_WRAPPING_KEY_TYPE_INCONSISTENT,
    RANDOM_SEED_NOT_SUPPORTED = c.CKR_RANDOM_SEED_NOT_SUPPORTED,
    RANDOM_NO_RNG = c.CKR_RANDOM_NO_RNG,
    DOMAIN_PARAMS_INVALID = c.CKR_DOMAIN_PARAMS_INVALID,
    CURVE_NOT_SUPPORTED = c.CKR_CURVE_NOT_SUPPORTED,
    BUFFER_TOO_SMALL = c.CKR_BUFFER_TOO_SMALL,
    SAVED_STATE_INVALID = c.CKR_SAVED_STATE_INVALID,
    INFORMATION_SENSITIVE = c.CKR_INFORMATION_SENSITIVE,
    STATE_UNSAVEABLE = c.CKR_STATE_UNSAVEABLE,
    CRYPTOKI_NOT_INITIALIZED = c.CKR_CRYPTOKI_NOT_INITIALIZED,
    CRYPTOKI_ALREADY_INITIALIZED = c.CKR_CRYPTOKI_ALREADY_INITIALIZED,
    MUTEX_BAD = c.CKR_MUTEX_BAD,
    MUTEX_NOT_LOCKED = c.CKR_MUTEX_NOT_LOCKED,
    NEW_PIN_MODE = c.CKR_NEW_PIN_MODE,
    NEXT_OTP = c.CKR_NEXT_OTP,
    EXCEEDED_MAX_ITERATIONS = c.CKR_EXCEEDED_MAX_ITERATIONS,
    FIPS_SELF_TEST_FAILED = c.CKR_FIPS_SELF_TEST_FAILED,
    LIBRARY_LOAD_FAILED = c.CKR_LIBRARY_LOAD_FAILED,
    PIN_TOO_WEAK = c.CKR_PIN_TOO_WEAK,
    PUBLIC_KEY_INVALID = c.CKR_PUBLIC_KEY_INVALID,
    FUNCTION_REJECTED = c.CKR_FUNCTION_REJECTED,
    VENDOR_DEFINED = c.CKR_VENDOR_DEFINED,
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

    const slots = try token.getSlotList(true);
    defer allocator.free(slots);
    try testing.expect(slots.len > 0);
    const slot = slots[0];

    const slot_info = try token.getSlotInfo(slot);
    try testing.expectStringStartsWith(&slot_info.description, "SoftHSM");
    try testing.expect(slot_info.flags.token_present);

    const info = try token.getInfo();
    try testing.expectStringStartsWith(&info.manufacturer_id, "SoftHSM");

    const token_info = try token.getTokenInfo(slot);
    try testing.expectStringStartsWith(&token_info.manufacturer_id, "SoftHSM");

    const mechs = try token.getMechanismList(slot);
    defer allocator.free(mechs);
    try testing.expect(mechs.len > 0);

    var mech_info = try token.getMechanismInfo(slot, MechanismType.aes_cbc);
    try testing.expect(mech_info.flags.encrypt);
    try testing.expect(mech_info.flags.decrypt);

    mech_info = try token.getMechanismInfo(slot, MechanismType.ec_key_pair_gen);
    try testing.expect(mech_info.flags.generate_key_pair);
    try testing.expect(mech_info.flags.ec.named_curve);
    try testing.expect(mech_info.flags.ec.uncompress);
}
