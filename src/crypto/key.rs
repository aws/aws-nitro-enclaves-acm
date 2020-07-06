use super::bignum_to_vec;
use super::ffi;
use super::FfiBox;
use super::{Error, Result};

#[derive(Eq, PartialEq)]
pub enum KeyAlgo {
    Ec,
    Rsa,
}

pub struct Pkey(FfiBox<ffi::EVP_PKEY>);

impl Pkey {
    pub fn from_private_pem(pem: &str) -> Result<Self> {
        let mut bio = FfiBox::new(unsafe {
            ffi::BIO_new_mem_buf(
                pem.as_ptr() as *const std::os::raw::c_void,
                pem.len() as i32,
            )
        })?;

        let pkey = FfiBox::new(unsafe {
            ffi::PEM_read_bio_PrivateKey(
                bio.as_mut_ptr(),
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null_mut(),
            )
        })?;

        Ok(Self(pkey))
    }

    pub fn algo(&self) -> Result<KeyAlgo> {
        match unsafe { ffi::EVP_PKEY_id(self.0.as_ptr()) } {
            ffi::EVP_PKEY_RSA => Ok(KeyAlgo::Rsa),
            ffi::EVP_PKEY_EC => Ok(KeyAlgo::Ec),
            _ => Err(Error::UnknownKeyType),
        }
    }

    pub fn num_bits(&self) -> Result<usize> {
        let rv = unsafe { ffi::EVP_PKEY_bits(self.as_ptr()) };
        if rv <= 0 {
            return Err(Error::GeneralError);
        }
        Ok(rv as usize)
    }

    /// Get the length (in bytes) for a signature perfomed by this Pkey.
    ///
    /// Note: signatures may have different formats. The value returned here concerns the
    ///       signature format yielded by the underlying libcrypto signing functions
    ///       (e.g. EVP_DigestSign*(), EVP_PKEY_sign(), etc).
    ///       This is important because the Cryptoki / PKCS#11 ABI uses a different format
    ///       for ECDSA signatures. Whereas libcryto DER-encodes ECDSA signatures, Cryptoki
    ///       uses a different, raw [R, S] format.
    pub fn sig_len(&self) -> Result<usize> {
        let rv = unsafe { ffi::EVP_PKEY_size(self.as_ptr()) };
        if rv <= 0 {
            return Err(Error::GeneralError);
        }
        Ok(rv as usize)
    }

    /// Get the length (in bytes) for a signature perfomed by this Pkey, when represented in
    /// the Cryptoki / PKCS#11 signature format.
    pub fn sig_len_ck(&self) -> Result<usize> {
        match self.algo()? {
            KeyAlgo::Ec => Ok((self.num_bits()? + 7) / 8 * 2),
            KeyAlgo::Rsa => self.sig_len(),
        }
    }

    pub fn rsa_modulus(&self) -> Result<Vec<u8>> {
        let rsa = self.rsa_key()?;
        let mut bn_ptr: *const ffi::BIGNUM = std::ptr::null();
        unsafe {
            // Note: RSA_get0_key just fetches / copies some pointers from the inner RSA struct,
            // so the BIGNUM structs are still owned by RSA. We are not taking ownership here.
            ffi::RSA_get0_key(
                rsa,
                &mut bn_ptr as *mut *const ffi::BIGNUM,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            );
        }
        // RSA_get0_key will always set the output params, so there's no need to check for
        // NULL on return. Also, bignum_to_vec already does param validation.
        bignum_to_vec(bn_ptr)
    }

    pub fn rsa_public_exponent(&self) -> Result<Vec<u8>> {
        let rsa = self.rsa_key()?;
        let mut bn_ptr: *const ffi::BIGNUM = std::ptr::null();
        unsafe {
            // Note: RSA_get0_key just fetches / copies some pointers from the inner RSA struct,
            // so the BIGNUM structs are still owned by RSA. We are not taking ownership here.
            ffi::RSA_get0_key(
                rsa,
                std::ptr::null_mut(),
                &mut bn_ptr as *mut *const ffi::BIGNUM,
                std::ptr::null_mut(),
            );
        }
        // RSA_get0_key will always set the output params, so there's no need to check for
        // NULL on return. Also, bignum_to_vec already does param validation.
        bignum_to_vec(bn_ptr)
    }

    pub fn ec_point_q_x962(&self) -> Result<Vec<u8>> {
        let ec = self.ec_key()?;
        let mut ctx = FfiBox::new(unsafe { ffi::BN_CTX_new() })?;
        let mut out_ptr: *mut std::os::raw::c_uchar = std::ptr::null_mut();
        let len = unsafe {
            ffi::EC_KEY_key2buf(
                ec,
                ffi::EC_KEY_get_conv_form(ec),
                &mut out_ptr,
                ctx.as_mut_ptr(),
            )
        };
        if len > 0 {
            let vec = unsafe { std::slice::from_raw_parts(out_ptr, len as usize).to_vec() };
            return Ok(vec);
        }
        Err(Error::GeneralError)
    }

    pub fn ec_params_x962(&self) -> Result<Vec<u8>> {
        let ec = self.ec_key()?;
        let group = unsafe { ffi::EC_KEY_get0_group(ec) };
        if group.is_null() {
            return Err(Error::BadKeyType);
        }
        // Get DER encoding of the curve
        let mut cbb = ffi::CBB::new()?;
        let rc = unsafe { ffi::EC_KEY_marshal_curve_name(&mut cbb as *mut ffi::CBB, group) };
        if rc != 1 {
            return Err(Error::GeneralError);
        }
        let der_len = unsafe { ffi::CBB_len(&cbb as *const ffi::CBB) as usize };
        let der = unsafe { ffi::CBB_data(&cbb as *const ffi::CBB) };
        let vec = unsafe { std::slice::from_raw_parts(der, der_len).to_vec() };

        Ok(vec)
    }

    pub fn as_ptr(&self) -> *const ffi::EVP_PKEY {
        self.0.as_ptr()
    }

    pub fn as_mut_ptr(&mut self) -> *mut ffi::EVP_PKEY {
        self.0.as_mut_ptr()
    }

    #[allow(dead_code)]
    pub fn into_raw(self) -> *mut ffi::EVP_PKEY {
        self.0.into_raw()
    }

    fn ec_key(&self) -> Result<*const ffi::EC_KEY> {
        let ec = unsafe { ffi::EVP_PKEY_get0_EC_KEY(self.as_ptr()) };
        if ec.is_null() {
            return Err(Error::BadKeyType);
        }
        Ok(ec)
    }

    fn rsa_key(&self) -> Result<*const ffi::RSA> {
        let rsa = unsafe { ffi::EVP_PKEY_get0_RSA(self.as_ptr()) };
        if rsa.is_null() {
            return Err(Error::BadKeyType);
        }
        Ok(rsa)
    }
}
