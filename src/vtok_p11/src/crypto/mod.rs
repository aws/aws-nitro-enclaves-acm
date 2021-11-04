// Copyright 2020-2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::pkcs11;

pub mod cert;
pub mod decrypt;
pub mod digest;
pub mod encrypt;
mod ffi;
pub mod key;
pub mod sign;
pub mod verify;

pub use cert::{CertCategory, X509Chain, X509};
pub use decrypt::{DecryptCtx, DirectDecryptCtx};
pub use digest::DigestCtx;
pub use encrypt::{DirectEncryptCtx, EncryptCtx};
pub use key::{KeyAlgo, Pkey};
pub use sign::{DigestSignCtx, DirectSignCtx, SignCtx};
pub use verify::{DigestVerifyCtx, DirectVerifyCtx, VerifyCtx};

use crate::backend::Mechanism;

/// Utility RAII wrappers for managing the cryptographic library interface
/// logic and also objects allocated through the backend cryptographic library

#[derive(Clone, Copy, Debug)]
pub enum Error {
    BadFlow,
    BadMech,
    BadMgf,
    BadSigFormat,
    BignumAlloc,
    DataMissing,
    Digest,
    DigestInit,
    DigestFinal,
    DigestSign,
    DigestSignFinal,
    DigestSignUpdate,
    DigestUpdate,
    DirectSign,
    MdCtxInit,
    GeneralError,
    OperationActive,
    PkeyCtxInit,
    PkeyCtxCtl,
    SignInit,
    VerifyInit,
    DigestVerify,
    DigestVerifyFinal,
    DigestVerifyUpdate,
    DirectVerify,
    DecryptInit,
    DirectDecrypt,
    EncryptInit,
    Encrypt,
    BadKeyType,
    UnknownKeyType,
    CertBadPem,
    CertName,
    CertIssuer,
    CertSerialNo,
    CertDerEncode,
    CertChainErr,
    CertChainInvalid,
}
pub type Result<T> = std::result::Result<T, Error>;

trait FfiFree {
    fn free(&mut self);
}

impl FfiFree for ffi::BIO {
    fn free(&mut self) {
        trace!("calling BIO_free");
        unsafe {
            ffi::BIO_free(self as *mut ffi::BIO);
        }
    }
}

impl FfiFree for ffi::EVP_MD_CTX {
    fn free(&mut self) {
        unsafe {
            ffi::EVP_MD_CTX_free(self as *mut ffi::EVP_MD_CTX);
        }
    }
}

impl FfiFree for ffi::EVP_PKEY {
    fn free(&mut self) {
        trace!("calling EVP_PKEY_free");
        unsafe {
            ffi::EVP_PKEY_free(self as *mut ffi::EVP_PKEY);
        }
    }
}

impl FfiFree for ffi::EVP_PKEY_CTX {
    fn free(&mut self) {
        unsafe {
            ffi::EVP_PKEY_CTX_free(self as *mut ffi::EVP_PKEY_CTX);
        }
    }
}

impl FfiFree for ffi::RSA {
    fn free(&mut self) {
        unsafe {
            ffi::RSA_free(self as *mut ffi::RSA);
        }
    }
}

impl FfiFree for ffi::EC_KEY {
    fn free(&mut self) {
        unsafe {
            ffi::EC_KEY_free(self as *mut ffi::EC_KEY);
        }
    }
}

impl FfiFree for ffi::BN_CTX {
    fn free(&mut self) {
        unsafe {
            ffi::BN_CTX_free(self as *mut ffi::BN_CTX);
        }
    }
}

impl FfiFree for ffi::ECDSA_SIG {
    fn free(&mut self) {
        unsafe {
            trace!("calling ECDSA_SIG_free");
            ffi::ECDSA_SIG_free(self as *mut ffi::ECDSA_SIG);
        }
    }
}

impl FfiFree for ffi::BIGNUM {
    fn free(&mut self) {
        unsafe {
            ffi::BN_free(self as *mut ffi::BIGNUM);
        }
    }
}

impl FfiFree for ffi::EC_GROUP {
    fn free(&mut self) {
        unsafe {
            ffi::EC_GROUP_free(self as *mut ffi::EC_GROUP);
        }
    }
}

impl FfiFree for ffi::EC_POINT {
    fn free(&mut self) {
        unsafe {
            ffi::EC_POINT_free(self as *mut ffi::EC_POINT);
        }
    }
}

impl FfiFree for ffi::X509 {
    fn free(&mut self) {
        unsafe {
            trace!("calling X509_free");
            ffi::X509_free(self as *mut ffi::X509);
        }
    }
}

impl FfiFree for ffi::X509_STORE {
    fn free(&mut self) {
        unsafe {
            trace!("calling X509_STORE_free");
            ffi::X509_STORE_free(self as *mut ffi::X509_STORE);
        }
    }
}

impl FfiFree for ffi::X509_STORE_CTX {
    fn free(&mut self) {
        unsafe {
            trace!("calling X509_STORE_CTX_free");
            ffi::X509_STORE_CTX_free(self as *mut ffi::X509_STORE_CTX);
        }
    }
}

struct FfiBox<T: FfiFree> {
    ptr: *mut T,
}
unsafe impl std::marker::Send for FfiBox<ffi::EVP_MD_CTX> {}
unsafe impl std::marker::Send for FfiBox<ffi::EVP_PKEY> {}
unsafe impl std::marker::Send for FfiBox<ffi::EVP_PKEY_CTX> {}
unsafe impl std::marker::Send for FfiBox<ffi::X509> {}
unsafe impl std::marker::Send for FfiBox<ffi::X509_STORE> {}
unsafe impl std::marker::Send for FfiBox<ffi::X509_STORE_CTX> {}

impl<T> FfiBox<T>
where
    T: FfiFree,
{
    pub fn new(ptr: *mut T) -> Result<Self> {
        if ptr.is_null() {
            Err(Error::GeneralError)
        } else {
            Ok(Self { ptr })
        }
    }

    pub fn as_ptr(&self) -> *const T {
        self.ptr
    }

    pub fn as_mut_ptr(&mut self) -> *mut T {
        self.ptr
    }

    pub fn into_raw(mut self) -> *mut T {
        let ret = self.ptr;
        self.ptr = std::ptr::null_mut();
        ret
    }
}

impl<T> Drop for FfiBox<T>
where
    T: FfiFree,
{
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe { (*self.ptr).free() }
        }
    }
}

/// Operation Context state. An operation context state is stored
/// in order to avoid misbehaving applications calling the incorrect
/// cryptographic intercaces (i.e. C_SignInit() -> C_Sign() -> C_SignUpdate())
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum OpCtxState {
    Initialized,
    SinglepartActive,
    MultipartActive,
    MultipartReady,
}

/// Convert a byte slice to a BIGNUM
fn bytes_to_bignum(src: &[u8]) -> Result<FfiBox<ffi::BIGNUM>> {
    FfiBox::new(unsafe {
        ffi::BN_bin2bn(
            src.as_ptr(),
            src.len() as ffi::c_size_t,
            std::ptr::null_mut(),
        )
    })
}

/// Convert an BIGNUM to a byte vector
fn bignum_to_vec(bn: *const ffi::BIGNUM) -> Result<Vec<u8>> {
    if bn.is_null() {
        return Err(Error::GeneralError);
    }
    let len = unsafe { ffi::BN_num_bytes(bn) };
    if len == 0 {
        return Err(Error::GeneralError);
    }
    let mut ret = vec![0u8; len as usize];

    let written = unsafe { ffi::BN_bn2bin(bn, ret.as_mut_ptr() as *mut i8) };
    if ret.len() != written as usize {
        return Err(Error::GeneralError);
    }
    Ok(ret)
}

/// Convert an PKCS#11 message digest type to an EVP MD type
fn mech_type_to_evp_md(mech_type: pkcs11::CK_MECHANISM_TYPE) -> Result<*const ffi::EVP_MD> {
    match mech_type {
        pkcs11::CKM_SHA_1
        | pkcs11::CKM_SHA1_RSA_PKCS
        | pkcs11::CKM_SHA1_RSA_PKCS_PSS
        | pkcs11::CKM_ECDSA_SHA1 => Ok(unsafe { ffi::EVP_sha1() }),
        pkcs11::CKM_SHA224
        | pkcs11::CKM_SHA224_RSA_PKCS
        | pkcs11::CKM_SHA224_RSA_PKCS_PSS
        | pkcs11::CKM_ECDSA_SHA224 => Ok(unsafe { ffi::EVP_sha224() }),
        pkcs11::CKM_SHA256
        | pkcs11::CKM_SHA256_RSA_PKCS
        | pkcs11::CKM_SHA256_RSA_PKCS_PSS
        | pkcs11::CKM_ECDSA_SHA256 => Ok(unsafe { ffi::EVP_sha256() }),
        pkcs11::CKM_SHA384
        | pkcs11::CKM_SHA384_RSA_PKCS
        | pkcs11::CKM_SHA384_RSA_PKCS_PSS
        | pkcs11::CKM_ECDSA_SHA384 => Ok(unsafe { ffi::EVP_sha384() }),
        pkcs11::CKM_SHA512
        | pkcs11::CKM_SHA512_RSA_PKCS
        | pkcs11::CKM_SHA512_RSA_PKCS_PSS
        | pkcs11::CKM_ECDSA_SHA512 => Ok(unsafe { ffi::EVP_sha512() }),
        _ => Err(Error::BadMech),
    }
}

/// Convert an PKCS#11 MGF type to an EVP MD type
fn mgf_to_evp_md(mgf: pkcs11::CK_RSA_PKCS_MGF_TYPE) -> Result<*const ffi::EVP_MD> {
    match mgf {
        pkcs11::CKG_MGF1_SHA1 => Ok(unsafe { ffi::EVP_sha1() }),
        pkcs11::CKG_MGF1_SHA224 => Ok(unsafe { ffi::EVP_sha224() }),
        pkcs11::CKG_MGF1_SHA256 => Ok(unsafe { ffi::EVP_sha256() }),
        pkcs11::CKG_MGF1_SHA384 => Ok(unsafe { ffi::EVP_sha384() }),
        pkcs11::CKG_MGF1_SHA512 => Ok(unsafe { ffi::EVP_sha512() }),
        _ => Err(Error::BadMgf),
    }
}

/// Convert an ECDSA signature from the Cryptoki [R,S] format to DER.
/// R or S are 0-padded so that each of them takes exactly half of the signature.
fn ecdsa_sig_ckrs_to_der(ckrs: &[u8]) -> Result<Vec<u8>> {
    let mut bn_r = bytes_to_bignum(&ckrs[..ckrs.len() / 2])?;
    let mut bn_s = bytes_to_bignum(&ckrs[ckrs.len() / 2..])?;

    let mut ec_sig = FfiBox::new(unsafe { ffi::ECDSA_SIG_new() })?;

    let rv =
        unsafe { ffi::ECDSA_SIG_set0(ec_sig.as_mut_ptr(), bn_r.as_mut_ptr(), bn_s.as_mut_ptr()) };
    if rv != 1 {
        return Err(Error::GeneralError);
    }
    // ec_sign now owns bn_r and bn_s; relinquish ownership.
    bn_r.into_raw();
    bn_s.into_raw();

    // i2d_ECDSA_SIG can either:
    // - fill in a caller-provided buffer (here, via *der_sig_ptr); or
    // - return a new buffer into the caller's ownership.
    // We are going with the former here, since we don't want to deal with OPENSSL_free().
    let der_sig_max_len = unsafe { ffi::ECDSA_SIG_max_len(ckrs.len() as u64 / 2) };
    let mut der_sig = vec![0u8; der_sig_max_len as usize];
    let mut der_sig_ptr = der_sig.as_mut_ptr();

    let der_sig_len = unsafe { ffi::i2d_ECDSA_SIG(ec_sig.as_ptr(), &mut der_sig_ptr) };
    if der_sig_len < 0 {
        return Err(Error::GeneralError);
    }
    der_sig.resize(der_sig_len as usize, 0);

    Ok(der_sig)
}

/// Convert a DER-encoded ECDSA signature to the Cryptoki [R,S] format, where either R
/// or S is 0-padded, so that they are exactly the same length, and:
/// R = sig[0 .. sig_len/2] and S = sig[sig_len/2 .. sig_len]
fn ecdsa_sig_der_to_ckrs(sig_der: &[u8]) -> Result<Vec<u8>> {
    let mut sig_der_ptr = sig_der.as_ptr();
    let ec_sig = FfiBox::new(unsafe {
        ffi::d2i_ECDSA_SIG(
            std::ptr::null_mut(),
            &mut sig_der_ptr,
            sig_der.len() as std::os::raw::c_long,
        )
    })?;

    let mut bn_r: *const ffi::BIGNUM = std::ptr::null();
    let mut bn_s: *const ffi::BIGNUM = std::ptr::null();
    unsafe { ffi::ECDSA_SIG_get0(ec_sig.as_ptr(), &mut bn_r, &mut bn_s) };
    if bn_r.is_null() || bn_s.is_null() {
        return Err(Error::GeneralError);
    }

    let r_len = unsafe { ffi::BN_num_bytes(bn_r) } as usize;
    let s_len = unsafe { ffi::BN_num_bytes(bn_s) } as usize;
    let order_len = if r_len >= s_len { r_len } else { s_len };

    let mut ret = vec![0u8; 2 * order_len];
    let rv = unsafe { ffi::BN_bn2bin_padded(ret.as_mut_ptr(), order_len as ffi::c_size_t, bn_r) };
    if rv != 1 {
        return Err(Error::GeneralError);
    }
    let rv = unsafe {
        ffi::BN_bn2bin_padded(
            ret[order_len..].as_mut_ptr(),
            order_len as ffi::c_size_t,
            bn_s,
        )
    };
    if rv != 1 {
        return Err(Error::GeneralError);
    }

    Ok(ret)
}

/// Configure the current EVP PKEY prior to a signing or a verification operation.
/// Depending on the RSA mechanism used, padding might differ.
/// ECDSA does not require any special handling
fn config_evp_pkey_ctx(pctx: *mut ffi::EVP_PKEY_CTX, mech: &Mechanism) -> Result<()> {
    let padding = match mech {
        Mechanism::Digest(_) => return Err(Error::BadMech),
        Mechanism::RsaX509 => ffi::RSA_NO_PADDING,
        Mechanism::RsaPkcs(_) => ffi::RSA_PKCS1_PADDING,
        Mechanism::RsaPkcsPss(_, _) => ffi::RSA_PKCS1_PSS_PADDING,
        Mechanism::Ecdsa(_) => return Ok(()),
    };
    let rc = unsafe { ffi::EVP_PKEY_CTX_set_rsa_padding(pctx, padding) };
    if rc != 1 {
        return Err(Error::PkeyCtxCtl);
    }

    if let Mechanism::RsaPkcsPss(_, Some(params)) = mech {
        let evp_md_hash = mech_type_to_evp_md(params.hashAlg)?;
        let rc = unsafe { ffi::EVP_PKEY_CTX_set_signature_md(pctx, evp_md_hash) };
        if rc != 1 {
            return Err(Error::PkeyCtxCtl);
        }
        let evp_md = mgf_to_evp_md(params.mgf)?;
        let rc = unsafe { ffi::EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, evp_md) };
        if rc != 1 {
            return Err(Error::PkeyCtxCtl);
        }

        let rc = unsafe {
            ffi::EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, params.sLen as std::os::raw::c_int)
        };
        if rc != 1 {
            return Err(Error::PkeyCtxCtl);
        }
    }

    Ok(())
}
