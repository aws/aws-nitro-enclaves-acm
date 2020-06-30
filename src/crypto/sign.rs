use crate::backend::Mechanism;

use super::ffi;
use super::{config_evp_pkey_ctx, mech_type_to_evp_md, ecdsa_sig_der_to_ckrs};
use super::{Error, FfiBox, OpCtxState, Pkey};
use super::key::KeyAlgo;

pub trait SignCtx: Send {
    fn update(&mut self, data: &[u8]) -> Result<(), Error>;
    fn finalize(self: Box<Self>) -> Result<Vec<u8>, Error>;
    fn sign(self: Box<Self>, data: &[u8]) -> Result<Vec<u8>, Error>;
    fn sig_len_ck(&self) -> usize;
    fn enter_state(&mut self, state: OpCtxState) -> Result<(), Error>;
}

pub struct DigestSignCtx {
    state: OpCtxState,
    evp_md_ctx: FfiBox<ffi::EVP_MD_CTX>,
    algo: KeyAlgo,
    sig_len: usize,
    sig_len_ck: usize,
}

pub struct DirectSignCtx {
    evp_pkey_ctx: FfiBox<ffi::EVP_PKEY_CTX>,
    algo: KeyAlgo,
    sig_len: usize,
    sig_len_ck: usize,
}

impl DigestSignCtx {
    pub fn new(mech: &Mechanism, mut pkey: Pkey) -> Result<Self, Error> {
        let mut evp_pkey_ctx: *mut ffi::EVP_PKEY_CTX = std::ptr::null_mut();
        let mut evp_md_ctx =
            FfiBox::new(unsafe { ffi::EVP_MD_CTX_new() }).map_err(|_| Error::MdCtxInit)?;

        let evp_md = mech_type_to_evp_md(mech.ck_type())?;

        let rc = unsafe {
            ffi::EVP_DigestSignInit(
                evp_md_ctx.as_mut_ptr(),
                &mut evp_pkey_ctx as *mut *mut ffi::EVP_PKEY_CTX,
                evp_md,
                std::ptr::null(),
                pkey.as_mut_ptr(),
            )
        };
        if rc != 1 {
            return Err(Error::SignInit);
        }

        config_evp_pkey_ctx(evp_pkey_ctx, mech)?;

        Ok(Self {
            state: OpCtxState::Initialized,
            evp_md_ctx,
            algo: pkey.algo()?,
            sig_len: pkey.sig_len()?,
            sig_len_ck: pkey.sig_len_ck()?,
        })
    }
}

impl SignCtx for DigestSignCtx {
    fn update(&mut self, data: &[u8]) -> Result<(), Error> {
        self.enter_state(OpCtxState::MultipartActive)?;
        let rc = unsafe {
            ffi::EVP_DigestSignUpdate(
                self.evp_md_ctx.as_mut_ptr(),
                data.as_ptr() as *const std::os::raw::c_void,
                data.len() as ffi::c_size_t,
            )
        };
        if rc != 1 {
            return Err(Error::DigestSignUpdate);
        }
        Ok(())
    }

    fn finalize(mut self: Box<Self>) -> Result<Vec<u8>, Error> {
        self.enter_state(OpCtxState::MultipartReady)?;
        let mut sig = vec![0u8; self.sig_len];
        let mut sig_len: ffi::c_size_t = self.sig_len as ffi::c_size_t;

        let rc = unsafe {
            ffi::EVP_DigestSignFinal(
                self.evp_md_ctx.as_mut_ptr(),
                sig.as_mut_ptr(),
                &mut sig_len as *mut ffi::c_size_t,
            )
        };
        if rc != 1 {
            return Err(Error::DigestSignFinal);
        }

        match self.algo {
            KeyAlgo::Ec => ecdsa_sig_der_to_ckrs(sig.as_slice()),
            KeyAlgo::Rsa => Ok(sig),
        }
    }

    fn sign(mut self: Box<Self>, data: &[u8]) -> Result<Vec<u8>, Error> {
        self.enter_state(OpCtxState::SinglepartActive)?;
        let mut sig = vec![0u8; self.sig_len];
        let mut sig_len: ffi::c_size_t = self.sig_len as ffi::c_size_t;

        let rc = unsafe {
            ffi::EVP_DigestSign(
                self.evp_md_ctx.as_mut_ptr(),
                sig.as_mut_ptr(),
                &mut sig_len as *mut ffi::c_size_t,
                data.as_ptr(),
                data.len() as ffi::c_size_t,
            )
        };
        if rc != 1 {
            return Err(Error::DigestSign);
        }

        match self.algo {
            KeyAlgo::Ec => ecdsa_sig_der_to_ckrs(sig.as_slice()),
            KeyAlgo::Rsa => Ok(sig),
        }
    }

    fn sig_len_ck(&self) -> usize {
        self.sig_len_ck
    }

    fn enter_state(&mut self, state: OpCtxState) -> Result<(), Error> {
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
}

impl DirectSignCtx {
    pub fn new(mech: &Mechanism, mut pkey: Pkey) -> Result<Self, Error> {
        let mut evp_pkey_ctx =
            FfiBox::new(unsafe { ffi::EVP_PKEY_CTX_new(pkey.as_mut_ptr(), std::ptr::null()) })
                .map_err(|_| Error::PkeyCtxInit)?;
        let rc = unsafe { ffi::EVP_PKEY_sign_init(evp_pkey_ctx.as_mut_ptr()) };
        if rc != 1 {
            return Err(Error::SignInit);
        }

        config_evp_pkey_ctx(evp_pkey_ctx.as_mut_ptr(), mech)?;

        Ok(Self {
            evp_pkey_ctx,
            algo: pkey.algo()?,
            sig_len: pkey.sig_len()?,
            sig_len_ck: pkey.sig_len_ck()?,
        })
    }
}

impl SignCtx for DirectSignCtx {
    fn sign(mut self: Box<Self>, data: &[u8]) -> Result<Vec<u8>, Error> {
        let mut sig = vec![0u8; self.sig_len];
        let mut sig_len: ffi::c_size_t = self.sig_len as ffi::c_size_t;

        let rc = unsafe {
            ffi::EVP_PKEY_sign(
                self.evp_pkey_ctx.as_mut_ptr(),
                sig.as_mut_ptr(),
                &mut sig_len as *mut ffi::c_size_t,
                data.as_ptr(),
                data.len() as ffi::c_size_t,
            )
        };
        if rc != 1 {
            return Err(Error::DirectSign);
        }

        let pkey = unsafe { ffi::EVP_PKEY_CTX_get0_pkey(self.evp_pkey_ctx.as_ptr()) };
        if pkey.is_null() {
            return Err(Error::GeneralError);
        }

        match self.algo {
            KeyAlgo::Ec => ecdsa_sig_der_to_ckrs(sig.as_slice()),
            KeyAlgo::Rsa => Ok(sig)
        }
    }

    fn sig_len_ck(&self) -> usize {
        self.sig_len_ck
    }

    fn enter_state(&mut self, state: OpCtxState) -> Result<(), Error> {
        if state == OpCtxState::SinglepartActive {
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
