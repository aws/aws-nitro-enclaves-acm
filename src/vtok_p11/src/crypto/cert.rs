// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::bignum_to_vec;
use super::ffi;
use super::FfiBox;
use super::{Error, Pkey, Result};

/// Logic for managing X509 public key certificates
/// These certificates are constructed from plain PEM files provided during
/// provisioning. The X509 is a wrapper over the generic X509
/// presented in the backend cryptographic library.
pub struct X509(FfiBox<ffi::X509>);

/// Certificate object type
#[derive(Clone)]
pub enum CertCategory {
    #[allow(dead_code)]
    /// Default (unverified)
    Unverified,
    /// Token certificate
    Token,
    /// CA certificate
    Authority,
    #[allow(dead_code)]
    /// Other
    Other,
}

impl X509 {
    /// Construct a certificate object from a BIO entry loaded with a
    /// certificate (or certificate chain) PEM file
    pub fn from_bio(bio: *mut ffi::BIO) -> Result<Self> {
        let cert = FfiBox::new(unsafe {
            ffi::PEM_read_bio_X509(
                bio,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null_mut(),
            )
        })?;

        Ok(Self(cert))
    }

    /// Get the certificate subject
    pub fn subject_name(&self) -> Result<Vec<u8>> {
        let name = unsafe { ffi::X509_get_subject_name(self.as_ptr()) };
        let pder = std::ptr::null();
        let mut pderlen: ffi::c_size_t = 0;
        let rc = unsafe { ffi::X509_NAME_get0_der(name, &pder, &mut pderlen) };
        if rc != 1 {
            return Err(Error::CertName);
        }
        if pderlen > 0 {
            let vec = unsafe { std::slice::from_raw_parts(pder, pderlen as usize).to_vec() };
            return Ok(vec);
        }
        Err(Error::CertName)
    }

    /// Get the certificate issuer
    pub fn issuer(&self) -> Result<Vec<u8>> {
        let issuer = unsafe { ffi::X509_get_issuer_name(self.as_ptr()) };
        let pder = std::ptr::null();
        let mut pderlen: ffi::c_size_t = 0;
        let rc = unsafe { ffi::X509_NAME_get0_der(issuer, &pder, &mut pderlen) };
        if rc != 1 {
            return Err(Error::CertIssuer);
        }
        if pderlen > 0 {
            let vec = unsafe { std::slice::from_raw_parts(pder, pderlen as usize).to_vec() };
            return Ok(vec);
        }
        Err(Error::CertIssuer)
    }

    /// Get the certificate serial number
    pub fn serial_no(&self) -> Result<Vec<u8>> {
        let asn1_sn = unsafe { ffi::X509_get0_serialNumber(self.as_ptr()) };
        let bn = unsafe { ffi::ASN1_INTEGER_to_BN(asn1_sn, std::ptr::null_mut()) };
        if bn.is_null() {
            return Err(Error::CertSerialNo);
        }
        let sn = bignum_to_vec(bn)?;
        unsafe { ffi::BN_free(bn) };
        Ok(sn)
    }

    /// PEM to DER X509 encoder. Needed as per pkcs#11 standard when storing certificates
    pub fn to_der(&self) -> Result<Vec<u8>> {
        let mut bio = FfiBox::new(unsafe { ffi::BIO_new(ffi::BIO_s_mem()) })?;
        let rv = unsafe { ffi::i2d_X509_bio(bio.as_mut_ptr(), self.as_ptr()) };
        if rv != 1 {
            return Err(Error::CertDerEncode);
        }
        let out_ptr = std::ptr::null();
        let mut out_ptr_len = 0;
        let rv = unsafe { ffi::BIO_mem_contents(bio.as_ptr(), &out_ptr, &mut out_ptr_len) };
        if rv != 1 {
            return Err(Error::CertDerEncode);
        }
        let vec = unsafe { std::slice::from_raw_parts(out_ptr, out_ptr_len as usize).to_vec() };
        Ok(vec)
    }

    pub fn as_ptr(&self) -> *const ffi::X509 {
        self.0.as_ptr()
    }

    #[allow(dead_code)]
    pub fn as_mut_ptr(&mut self) -> *mut ffi::X509 {
        self.0.as_mut_ptr()
    }
}

/// Container for holding a certificate or a chain of certificates
/// Parses the input X509 PEM and constructs X509 objects in the order
/// of certificate_list from RFC4346:
/// - Server Certificate
/// - One or more intermediary certificates
/// - Root CA certificate (optional)
/// Each certificate validates the one preceeding it
pub struct X509Chain {
    cert_chain: Vec<X509>,
}

impl X509Chain {
    /// Construct a chain of X509 objects from a certificate PEM file
    pub fn chain_from_pem(pem: &str) -> Result<Self> {
        let mut bio = FfiBox::new(unsafe {
            ffi::BIO_new_mem_buf(
                pem.as_ptr() as *const std::os::raw::c_void,
                pem.len() as i32,
            )
        })?;
        let mut cert_chain = Vec::new();
        loop {
            if let Ok(cert) = X509::from_bio(bio.as_mut_ptr()) {
                cert_chain.push(cert);
            } else {
                // No more entries. Check if EOF or bad PEM entries
                let rv = unsafe { ffi::BIO_eof(bio.as_mut_ptr()) };
                if rv == 0 {
                    return Err(Error::CertBadPem);
                }
                break;
            }
        }
        Ok(Self {
            cert_chain: cert_chain,
        })
    }

    /// Validate the entire certificate chain against the server certificate
    pub fn verify_chain(&self) -> Result<()> {
        let mut cert_store = FfiBox::new(unsafe { ffi::X509_STORE_new() })?;
        let mut rv = unsafe {
            ffi::X509_STORE_set_flags(cert_store.as_mut_ptr(), ffi::X509_V_FLAG_X509_STRICT)
        };
        if rv != 1 {
            return Err(Error::CertChainErr);
        }
        for (pos, cert) in self.enumerate() {
            if pos > 0 {
                // Only intermediate and root certificates are stored for verification
                rv = unsafe { ffi::X509_STORE_add_cert(cert_store.as_mut_ptr(), cert.as_ptr()) };
                if rv != 1 {
                    return Err(Error::CertChainErr);
                }
            }
        }
        let mut cert_store_ctx = FfiBox::new(unsafe { ffi::X509_STORE_CTX_new() })?;
        rv = unsafe {
            ffi::X509_STORE_CTX_init(
                cert_store_ctx.as_mut_ptr(),
                cert_store.as_mut_ptr(),
                self.cert_chain.first().ok_or(Error::CertChainErr)?.as_ptr(),
                std::ptr::null_mut(),
            )
        };
        if rv != 1 {
            return Err(Error::CertChainErr);
        }
        // Set the purpose explicitly to avoid invalidation via
        // any special X509.V3 features.
        unsafe {
            ffi::X509_STORE_CTX_set_purpose(cert_store_ctx.as_mut_ptr(), ffi::X509_PURPOSE_ANY)
        };
        // Issue the verification
        rv = unsafe { ffi::X509_verify_cert(cert_store_ctx.as_mut_ptr()) };
        if rv != 1 {
            return Err(Error::CertChainErr);
        }
        unsafe { ffi::X509_STORE_CTX_cleanup(cert_store_ctx.as_mut_ptr()) };

        Ok(())
    }

    /// Verify if the server certificate matches its private key.
    /// Shall fail if it is part of a trust chain
    pub fn verify(&self, pkey: Pkey) -> Result<()> {
        let rv = unsafe {
            ffi::X509_verify(
                self.cert_chain.first().ok_or(Error::CertChainErr)?.as_ptr(),
                pkey.as_ptr(),
            )
        };
        if rv != 1 {
            return Err(Error::CertChainErr);
        }
        Ok(())
    }

    /// Returns true if a bundle of certificates was provisioned
    pub fn multiple_certs(&self) -> bool {
        self.cert_chain.len() > 1
    }

    pub fn enumerate(&self) -> impl Iterator<Item = (u8, &X509)> {
        self.cert_chain
            .iter()
            .enumerate()
            .map(|(index, cert)| (index as u8, cert))
    }
}
