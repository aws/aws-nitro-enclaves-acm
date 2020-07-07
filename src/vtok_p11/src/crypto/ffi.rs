#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

use std::os::raw::{c_char, c_int, c_long, c_uchar, c_uint, c_ulong, c_void};
pub type c_size_t = c_ulong;

/// The low level backend cryptographic interface used by this module.
/// Built on top of the backend cryptographic library (i.e. BoringSSL,
/// OpenSSL, AWS Crypto). See the library documentation for each entries
/// found here, depending on which one is linked at run-time.

/// Maximum message digest size
pub const EVP_MAX_MD_SIZE: usize = 64;

/// RSA padding types
pub const RSA_PKCS1_PADDING: c_int = 1;
pub const RSA_NO_PADDING: c_int = 3;
pub const RSA_PKCS1_PSS_PADDING: c_int = 6;

/// EVP_PKEY types
pub const EVP_PKEY_RSA: c_int = 6;
pub const EVP_PKEY_EC: c_int = 408;

/// Opaque cryptographic objects
#[repr(C)]
pub struct BIGNUM {
    _ph: [u8; 0],
}
#[repr(C)]
pub struct BIO {
    _ph: [u8; 0],
}
#[repr(C)]
pub struct ENGINE {
    _ph: [u8; 0],
}
#[repr(C)]
pub struct EVP_MD {
    _ph: [u8; 0],
}
#[repr(C)]
pub struct EVP_MD_CTX {
    _ph: [u8; 0],
}
#[repr(C)]
pub struct EVP_PKEY {
    _ph: [u8; 0],
}
#[repr(C)]
pub struct EVP_PKEY_CTX {
    _ph: [u8; 0],
}
#[repr(C)]
pub struct RSA {
    _ph: [u8; 0],
}
#[repr(C)]
pub struct EC_KEY {
    _ph: [u8; 0],
}
#[repr(C)]
pub struct EC_POINT {
    _ph: [u8; 0],
}
#[repr(C)]
pub struct EC_GROUP {
    _ph: [u8; 0],
}
#[repr(C)]
pub struct BN_CTX {
    _ph: [u8; 0],
}
#[repr(C)]
pub struct ECDSA_SIG {
    _ph: [u8; 0],
}

/// Transparent cryptographic objects
#[repr(C)]
pub struct cbb_buffer_st {
    buf: *mut u8,
    len: c_size_t,
    cap: c_size_t,
    can_resize: c_char,
    error: c_char,
}
#[repr(C)]
pub struct cbb_st {
    base: *mut cbb_buffer_st,
    child: *mut CBB,
    offset: c_size_t,
    pending_len_len: u8,
    pending_is_asn1: c_char,
    is_child: c_char,
}
pub type CBB = cbb_st;

impl CBB {
    pub fn new() -> Result<Self, super::Error> {
        let mut cbb = std::mem::MaybeUninit::uninit();
        if unsafe { CBB_init(cbb.as_mut_ptr(), 0) } != 1 {
            return Err(super::Error::GeneralError);
        }
        Ok(unsafe { cbb.assume_init() })
    }
}
impl Drop for CBB {
    fn drop(&mut self) {
        unsafe {
            CBB_cleanup(self as *mut CBB);
        }
    }
}

/// Imported cryptographic APIs
extern "C" {
    /// Private key utility functions (i.e. from PEM)
    pub fn BIO_new_mem_buf(buf: *const c_void, len: c_int) -> *mut BIO;

    pub fn BIO_free(bio: *mut BIO) -> c_int;

    pub fn PEM_read_bio_PrivateKey(
        bp: *mut BIO,
        x: *mut *mut EVP_PKEY,
        cb: *const c_void,
        u: *mut c_void,
    ) -> *mut EVP_PKEY;

    /// Message digest constants
    pub fn EVP_sha1() -> *const EVP_MD;
    pub fn EVP_sha224() -> *const EVP_MD;
    pub fn EVP_sha256() -> *const EVP_MD;
    pub fn EVP_sha384() -> *const EVP_MD;
    pub fn EVP_sha512() -> *const EVP_MD;
    pub fn EVP_MD_size(md: *const EVP_MD) -> c_int;

    pub fn EVP_MD_CTX_new() -> *mut EVP_MD_CTX;
    pub fn EVP_MD_CTX_free(ctx: *mut EVP_MD_CTX);

    /// Message Digest functions
    pub fn EVP_DigestInit_ex(
        ctx: *mut EVP_MD_CTX,
        type_: *const EVP_MD,
        engine: *mut c_void,
    ) -> c_int;
    pub fn EVP_DigestUpdate(ctx: *mut EVP_MD_CTX, d: *const c_void, cnt: c_size_t) -> c_int;
    pub fn EVP_DigestFinal_ex(ctx: *mut EVP_MD_CTX, md: *mut c_uchar, s: *mut c_uint) -> c_int;
    pub fn EVP_Digest(
        data: *const c_void,
        len: c_size_t,
        md_out: *mut u8,
        md_out_size: *mut c_uint,
        type_: *const EVP_MD,
        impl_: *mut ENGINE,
    ) -> c_int;

    /// Sign functions
    pub fn EVP_PKEY_sign_init(ctx: *mut EVP_PKEY_CTX) -> c_int;
    pub fn EVP_PKEY_sign(
        ctx: *mut EVP_PKEY_CTX,
        sig: *mut c_uchar,
        siglen: *mut c_size_t,
        tbs: *const c_uchar,
        tbslen: c_size_t,
    ) -> c_int;
    pub fn EVP_DigestSignInit(
        ctx: *mut EVP_MD_CTX,
        pctx: *mut *mut EVP_PKEY_CTX,
        type_: *const EVP_MD,
        e: *const c_void,
        pkey: *mut EVP_PKEY,
    ) -> c_int;
    pub fn EVP_DigestSignUpdate(ctx: *mut EVP_MD_CTX, d: *const c_void, cnt: c_size_t) -> c_int;
    pub fn EVP_DigestSignFinal(
        ctx: *mut EVP_MD_CTX,
        sig: *mut c_uchar,
        siglen: *mut c_size_t,
    ) -> c_int;
    pub fn EVP_DigestSign(
        ctx: *mut EVP_MD_CTX,
        out_sig: *mut u8,
        out_sig_len: *mut c_size_t,
        data: *const u8,
        data_len: c_size_t,
    ) -> c_int;

    /// Verify functions
    pub fn EVP_PKEY_verify_init(ctx: *mut EVP_PKEY_CTX) -> c_int;
    pub fn EVP_PKEY_verify(
        ctx: *mut EVP_PKEY_CTX,
        sig: *const c_uchar,
        sig_len: c_size_t,
        digest: *const c_uchar,
        digest_len: c_size_t,
    ) -> c_int;
    pub fn EVP_DigestVerifyInit(
        ctx: *mut EVP_MD_CTX,
        pctx: *mut *mut EVP_PKEY_CTX,
        type_: *const EVP_MD,
        e: *const c_void,
        pkey: *mut EVP_PKEY,
    ) -> c_int;
    pub fn EVP_DigestVerifyUpdate(
        ctx: *mut EVP_MD_CTX,
        data: *const c_void,
        len: c_size_t,
    ) -> c_int;
    pub fn EVP_DigestVerifyFinal(
        ctx: *mut EVP_MD_CTX,
        sig: *const c_uchar,
        sig_len: c_size_t,
    ) -> c_int;
    pub fn EVP_DigestVerify(
        ctx: *mut EVP_MD_CTX,
        sig: *const c_uchar,
        sig_len: c_size_t,
        data: *const c_uchar,
        len: c_size_t,
    ) -> c_int;

    /// Decryption functions
    pub fn EVP_PKEY_decrypt_init(ctx: *mut EVP_PKEY_CTX) -> c_int;
    pub fn EVP_PKEY_decrypt(
        ctx: *mut EVP_PKEY_CTX,
        out: *mut u8,
        out_len: *mut c_size_t,
        in_: *const u8,
        in_len: c_size_t,
    ) -> c_int;

    /// Encryption functions
    pub fn EVP_PKEY_encrypt_init(ctx: *mut EVP_PKEY_CTX) -> c_int;
    pub fn EVP_PKEY_encrypt(
        ctx: *mut EVP_PKEY_CTX,
        out: *mut u8,
        out_len: *mut c_size_t,
        in_: *const u8,
        in_len: c_size_t,
    ) -> c_int;

    /// Generic EVP PKEY container functions
    pub fn EVP_PKEY_free(key: *mut EVP_PKEY);
    pub fn EVP_PKEY_bits(key: *const EVP_PKEY) -> c_int;
    pub fn EVP_PKEY_size(key: *const EVP_PKEY) -> c_int;
    pub fn EVP_PKEY_id(key: *const EVP_PKEY) -> c_int;

    /// Generic EVP PKEY context functions
    pub fn EVP_PKEY_CTX_new(pkey: *mut EVP_PKEY, e: *const c_void) -> *mut EVP_PKEY_CTX;
    pub fn EVP_PKEY_CTX_free(ctx: *mut EVP_PKEY_CTX);
    pub fn EVP_PKEY_CTX_get0_pkey(ctx: *const EVP_PKEY_CTX) -> *const EVP_PKEY;
    pub fn EVP_PKEY_CTX_set_signature_md(ctx: *mut EVP_PKEY_CTX, md: *const EVP_MD) -> c_int;

    /// RSA key specific functions
    pub fn EVP_PKEY_get0_RSA(pkey: *const EVP_PKEY) -> *const RSA;
    // Note: OpenSSL doesn't export these, implementing them as a macros instead.
    pub fn EVP_PKEY_CTX_set_rsa_padding(ctx: *mut EVP_PKEY_CTX, pad: c_int) -> c_int;
    pub fn EVP_PKEY_CTX_set_rsa_mgf1_md(ctx: *mut EVP_PKEY_CTX, md: *const EVP_MD) -> c_int;
    pub fn EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx: *mut EVP_PKEY_CTX, len: c_int) -> c_int;
    pub fn RSA_get0_key(
        rsa: *const RSA,
        out_n: *mut *const BIGNUM,
        out_e: *mut *const BIGNUM,
        out_d: *mut *const BIGNUM,
    );
    pub fn RSA_free(rsa: *mut RSA);

    /// EC key specific functions
    pub fn EVP_PKEY_get0_EC_KEY(pkey: *const EVP_PKEY) -> *mut EC_KEY;
    pub fn EC_KEY_key2buf(
        ec: *const EC_KEY,
        form: c_int,
        out_buf: *mut *mut c_uchar,
        ctx: *mut BN_CTX,
    ) -> c_size_t;
    pub fn EC_KEY_get0_group(key: *const EC_KEY) -> *const EC_GROUP;
    pub fn EC_KEY_marshal_curve_name(cbb: *mut CBB, group: *const EC_GROUP) -> c_int;
    pub fn EC_KEY_get_conv_form(ec: *const EC_KEY) -> c_int; // point_conversion_form_t enum
    pub fn EC_KEY_free(ec: *mut EC_KEY);
    pub fn ECDSA_SIG_get0(
        sig: *const ECDSA_SIG,
        out_r: *mut *const BIGNUM,
        our_s: *mut *const BIGNUM,
    );
    pub fn d2i_ECDSA_SIG(
        sig: *mut *mut ECDSA_SIG,
        pp: *mut *const c_uchar,
        len: c_long,
    ) -> *mut ECDSA_SIG;
    pub fn i2d_ECDSA_SIG(sig: *const ECDSA_SIG, outp: *mut *mut u8) -> c_int;
    pub fn ECDSA_SIG_set0(sig: *mut ECDSA_SIG, r: *mut BIGNUM, s: *mut BIGNUM) -> c_int;
    pub fn ECDSA_SIG_new() -> *mut ECDSA_SIG;
    pub fn ECDSA_SIG_free(sig: *mut ECDSA_SIG);
    pub fn ECDSA_SIG_max_len(order_len: c_size_t) -> c_size_t;

    pub fn EC_POINT_free(point: *mut EC_POINT);
    pub fn EC_GROUP_free(group: *mut EC_GROUP);

    /// CBB helper functions
    pub fn CBB_init(cbb: *mut CBB, initial_capacity: c_size_t) -> c_int;
    pub fn CBB_cleanup(cbb: *mut CBB);
    pub fn CBB_data(cbb: *const CBB) -> *const u8;
    pub fn CBB_len(cbb: *const CBB) -> c_size_t;

    /// BIGNUM helper functions
    pub fn BN_num_bytes(bn: *const BIGNUM) -> c_uint;
    pub fn BN_bn2bin(bn: *const BIGNUM, to: *mut c_char) -> c_int;
    pub fn BN_bn2bin_padded(out: *mut u8, len: c_size_t, in_: *const BIGNUM) -> c_int;
    pub fn BN_bin2bn(in_: *const u8, len: c_size_t, ret: *mut BIGNUM) -> *mut BIGNUM;
    pub fn BN_CTX_new() -> *mut BN_CTX;
    pub fn BN_CTX_free(ctx: *mut BN_CTX);
    pub fn BN_free(bn: *mut BIGNUM);
}
