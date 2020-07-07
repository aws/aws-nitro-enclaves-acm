use crate::backend::Mechanism;

use super::config_evp_pkey_ctx;
use super::ffi;
use super::{Error, FfiBox, OpCtxState, Pkey};

/// Encryption context logic interfacing the cryptographic backend library
/// Each session can have one active encryption context at a time

pub trait EncryptCtx: Send {
    fn update(&mut self, data: &[u8]) -> Result<(), Error>;
    fn finalize(self: Box<Self>) -> Result<Vec<u8>, Error>;
    fn encrypt(self: Box<Self>, data: &[u8]) -> Result<Vec<u8>, Error>;
    fn len(&self) -> usize;
    fn enter_state(&mut self, state: OpCtxState) -> Result<(), Error>;
}

pub struct DirectEncryptCtx {
    evp_pkey_ctx: FfiBox<ffi::EVP_PKEY_CTX>,
    encrypt_len: usize,
}

impl DirectEncryptCtx {
    pub fn new(mech: &Mechanism, mut key: Pkey) -> Result<Self, Error> {
        let mut evp_pkey_ctx =
            FfiBox::new(unsafe { ffi::EVP_PKEY_CTX_new(key.as_mut_ptr(), std::ptr::null()) })
                .map_err(|_| Error::PkeyCtxInit)?;

        let rc = unsafe { ffi::EVP_PKEY_encrypt_init(evp_pkey_ctx.as_mut_ptr()) };
        if rc != 1 {
            return Err(Error::EncryptInit);
        }
        config_evp_pkey_ctx(evp_pkey_ctx.as_mut_ptr(), mech)?;

        let encrypt_len = unsafe { ffi::EVP_PKEY_size(key.as_ptr()) as usize };

        Ok(Self {
            evp_pkey_ctx,
            encrypt_len,
        })
    }
}

impl EncryptCtx for DirectEncryptCtx {
    fn encrypt(mut self: Box<Self>, data: &[u8]) -> Result<Vec<u8>, Error> {
        let mut enc = vec![0u8; self.encrypt_len];
        let mut encrypt_len: ffi::c_size_t = self.encrypt_len as ffi::c_size_t;

        let rc = unsafe {
            ffi::EVP_PKEY_encrypt(
                self.evp_pkey_ctx.as_mut_ptr(),
                enc.as_mut_ptr(),
                &mut encrypt_len as *mut ffi::c_size_t,
                data.as_ptr(),
                data.len() as ffi::c_size_t,
            )
        };
        if rc != 1 {
            return Err(Error::Encrypt);
        }

        enc.resize(encrypt_len as usize, 0);
        Ok(enc)
    }

    fn len(&self) -> usize {
        self.encrypt_len
    }

    fn enter_state(&mut self, state: OpCtxState) -> Result<(), Error> {
        if let OpCtxState::SinglepartActive = state {
            Ok(())
        } else {
            Err(Error::OperationActive)
        }
    }

    fn update(&mut self, _data: &[u8]) -> Result<(), Error> {
        Err(Error::OperationActive)
    }
    fn finalize(self: Box<Self>) -> Result<Vec<u8>, Error> {
        Err(Error::OperationActive)
    }
}
