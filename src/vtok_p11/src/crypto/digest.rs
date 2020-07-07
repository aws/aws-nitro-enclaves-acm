use crate::pkcs11;

use super::ffi;
use super::mech_type_to_evp_md;
use super::Error;
use super::FfiBox;
use super::OpCtxState;

/// Message digest context logic interfacing the cryptographic backend library
/// Each session can have one active message digest context at a time

pub struct DigestCtx {
    state: OpCtxState,
    digest_len: usize,
    evp_ctx: FfiBox<ffi::EVP_MD_CTX>,
    mech_type: pkcs11::CK_MECHANISM_TYPE,
}

impl DigestCtx {
    pub fn new(mech_type: pkcs11::CK_MECHANISM_TYPE) -> Result<Self, Error> {
        let evp_md = mech_type_to_evp_md(mech_type)?;
        let mut evp_ctx = FfiBox::new(unsafe { ffi::EVP_MD_CTX_new() })?;

        let rv =
            unsafe { ffi::EVP_DigestInit_ex(evp_ctx.as_mut_ptr(), evp_md, std::ptr::null_mut()) };
        if rv == 0 {
            return Err(Error::DigestInit);
        }

        let digest_len = unsafe { ffi::EVP_MD_size(evp_md) };

        Ok(Self {
            state: OpCtxState::Initialized,
            digest_len: digest_len as usize,
            evp_ctx,
            mech_type,
        })
    }

    pub fn len(&self) -> usize {
        self.digest_len
    }

    pub fn enter_state(&mut self, state: OpCtxState) -> Result<(), Error> {
        let ret = match (self.state, state) {
            (OpCtxState::Initialized, _) => Ok(()),
            (OpCtxState::SinglepartActive, OpCtxState::SinglepartActive) => Ok(()),
            (OpCtxState::SinglepartActive, _) => Err(Error::OperationActive),
            (OpCtxState::MultipartActive, OpCtxState::MultipartActive) => Ok(()),
            (OpCtxState::MultipartActive, OpCtxState::MultipartReady) => Ok(()),
            (OpCtxState::MultipartActive, _) => Err(Error::OperationActive),
            (OpCtxState::MultipartReady, OpCtxState::MultipartReady) => Ok(()),
            (OpCtxState::MultipartReady, _) => Err(Error::OperationActive),
        };
        if ret.is_ok() {
            self.state = state;
        }
        ret
    }

    pub fn update(&mut self, data: &[u8]) -> Result<(), Error> {
        self.enter_state(OpCtxState::MultipartActive)?;

        let rv = unsafe {
            ffi::EVP_DigestUpdate(
                self.evp_ctx.as_mut_ptr(),
                data.as_ptr() as *const std::os::raw::c_void,
                data.len() as std::os::raw::c_ulong,
            )
        };
        if rv == 0 {
            return Err(Error::DigestUpdate);
        }
        self.state = OpCtxState::MultipartActive;
        Ok(())
    }

    pub fn finalize(mut self) -> Result<Vec<u8>, Error> {
        self.enter_state(OpCtxState::MultipartReady)?;

        let mut ret = vec![0u8; ffi::EVP_MAX_MD_SIZE];
        let mut len: std::os::raw::c_uint = 0;
        let rv = unsafe {
            ffi::EVP_DigestFinal_ex(
                self.evp_ctx.as_mut_ptr(),
                ret.as_mut_ptr(),
                &mut len as *mut std::os::raw::c_uint,
            )
        };
        if rv == 0 {
            return Err(Error::DigestFinal);
        }
        ret.resize(len as usize, 0);
        Ok(ret)
    }

    pub fn digest(mut self, data: &[u8]) -> Result<Vec<u8>, Error> {
        self.enter_state(OpCtxState::SinglepartActive)?;

        let evp_md = mech_type_to_evp_md(self.mech_type)?;
        let mut md_out = vec![0u8; self.digest_len];
        let mut md_out_len: std::os::raw::c_uint = self.digest_len as std::os::raw::c_uint;
        let rv = unsafe {
            ffi::EVP_Digest(
                data.as_ptr() as *const std::os::raw::c_void,
                data.len() as ffi::c_size_t,
                md_out.as_mut_ptr(),
                &mut md_out_len as *mut std::os::raw::c_uint,
                evp_md,
                std::ptr::null_mut(),
            )
        };
        if rv != 1 {
            return Err(Error::Digest);
        }
        Ok(md_out.to_vec())
    }
}
