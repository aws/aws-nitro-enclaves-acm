use crate::backend::Mechanism;

use super::config_evp_pkey_ctx;
use super::ffi;
use super::{Error, FfiBox, OpCtxState, Pkey};

pub trait DecryptCtx: Send {
    fn update(&mut self, data: &[u8]) -> Result<(), Error>;
    fn finalize(self: Box<Self>) -> Result<Vec<u8>, Error>;
    fn decrypt(self: Box<Self>, data: &[u8]) -> Result<Vec<u8>, Error>;
    fn len(&self) -> usize;
    fn enter_state(&mut self, state: OpCtxState) -> Result<(), Error>;
}

pub struct DirectDecryptCtx {
    evp_pkey_ctx: FfiBox<ffi::EVP_PKEY_CTX>,
    decrypt_len: usize,
}

impl DirectDecryptCtx {
    pub fn new(mech: &Mechanism, mut key: Pkey) -> Result<Self, Error> {
        let mut evp_pkey_ctx =
            FfiBox::new(unsafe { ffi::EVP_PKEY_CTX_new(key.as_mut_ptr(), std::ptr::null()) })
                .map_err(|_| Error::PkeyCtxInit)?;

        let rc = unsafe { ffi::EVP_PKEY_decrypt_init(evp_pkey_ctx.as_mut_ptr()) };
        if rc != 1 {
            return Err(Error::DecryptInit);
        }

        config_evp_pkey_ctx(evp_pkey_ctx.as_mut_ptr(), mech)?;

        // Asymmetric decryption outputs up to modulus size bytes
        let decrypt_len = unsafe { ffi::EVP_PKEY_size(key.as_ptr()) as usize };

        Ok(Self {
            evp_pkey_ctx,
            decrypt_len,
        })
    }
}

impl DecryptCtx for DirectDecryptCtx {
    fn decrypt(mut self: Box<Self>, encrypted_data: &[u8]) -> Result<Vec<u8>, Error> {
        let mut data = vec![0u8; self.decrypt_len];
        let mut data_len: ffi::c_size_t = self.decrypt_len as ffi::c_size_t;

        let rc = unsafe {
            ffi::EVP_PKEY_decrypt(
                self.evp_pkey_ctx.as_mut_ptr(),
                data.as_mut_ptr(),
                &mut data_len as *mut ffi::c_size_t,
                encrypted_data.as_ptr(),
                encrypted_data.len() as ffi::c_size_t,
            )
        };

        if rc != 1 {
            return Err(Error::DirectDecrypt);
        }

        // Resize to actual length
        data.resize(data_len as usize, 0);
        Ok(data.to_vec())
    }

    fn len(&self) -> usize {
        self.decrypt_len
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
