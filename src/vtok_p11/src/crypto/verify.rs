use crate::backend::Mechanism;

use super::ffi;
use super::key::KeyAlgo;
use super::{config_evp_pkey_ctx, ecdsa_sig_ckrs_to_der, mech_type_to_evp_md};
use super::{Error, FfiBox, OpCtxState, Pkey};

/// Verifying context logic interfacing the cryptographic backend library
/// Each session can have one active verifying context at a time

pub trait VerifyCtx: Send {
    fn update(&mut self, data: &[u8]) -> Result<(), Error>;
    fn finalize(self: Box<Self>, signature: &[u8]) -> Result<(), Error>;
    fn verify(self: Box<Self>, data: &[u8], signature: &[u8]) -> Result<(), Error>;
    fn verify_sig_len_ck(&self, sig_len_ck: usize) -> bool;
    fn enter_state(&mut self, state: OpCtxState) -> Result<(), Error>;
}

pub struct DigestVerifyCtx {
    state: OpCtxState,
    evp_md_ctx: FfiBox<ffi::EVP_MD_CTX>,
    algo: KeyAlgo,
    sig_len_ck: usize,
}

pub struct DirectVerifyCtx {
    evp_pkey_ctx: FfiBox<ffi::EVP_PKEY_CTX>,
    algo: KeyAlgo,
    sig_len_ck: usize,
}

impl DigestVerifyCtx {
    pub fn new(mech: &Mechanism, mut pkey: Pkey) -> Result<Self, Error> {
        let mut evp_pkey_ctx: *mut ffi::EVP_PKEY_CTX = std::ptr::null_mut();
        let mut evp_md_ctx =
            FfiBox::new(unsafe { ffi::EVP_MD_CTX_new() }).map_err(|_| Error::MdCtxInit)?;

        let evp_md = mech_type_to_evp_md(mech.ck_type())?;

        let rc = unsafe {
            ffi::EVP_DigestVerifyInit(
                evp_md_ctx.as_mut_ptr(),
                &mut evp_pkey_ctx as *mut *mut ffi::EVP_PKEY_CTX,
                evp_md,
                std::ptr::null(),
                pkey.as_mut_ptr(),
            )
        };
        if rc != 1 {
            return Err(Error::VerifyInit);
        }

        config_evp_pkey_ctx(evp_pkey_ctx, mech)?;

        Ok(Self {
            state: OpCtxState::Initialized,
            evp_md_ctx,
            algo: pkey.algo()?,
            sig_len_ck: pkey.sig_len_ck()?,
        })
    }
}

impl VerifyCtx for DigestVerifyCtx {
    fn update(&mut self, data: &[u8]) -> Result<(), Error> {
        self.enter_state(OpCtxState::MultipartActive)?;

        let rc = unsafe {
            ffi::EVP_DigestVerifyUpdate(
                self.evp_md_ctx.as_mut_ptr(),
                data.as_ptr() as *const std::os::raw::c_void,
                data.len() as std::os::raw::c_ulong,
            )
        };
        if rc != 1 {
            return Err(Error::DigestVerifyUpdate);
        }

        Ok(())
    }

    fn finalize(mut self: Box<Self>, signature: &[u8]) -> Result<(), Error> {
        self.enter_state(OpCtxState::MultipartReady)?;

        let rc = unsafe {
            ffi::EVP_DigestVerifyFinal(
                self.evp_md_ctx.as_mut_ptr(),
                signature.as_ptr() as *const std::os::raw::c_uchar,
                signature.len() as std::os::raw::c_ulong,
            )
        };
        if rc != 1 {
            return Err(Error::DigestVerifyFinal);
        }
        Ok(())
    }

    fn verify(mut self: Box<Self>, data: &[u8], signature: &[u8]) -> Result<(), Error> {
        self.enter_state(OpCtxState::SinglepartActive)?;

        let crypto_sig = match self.algo {
            KeyAlgo::Ec => ecdsa_sig_ckrs_to_der(signature)?,
            KeyAlgo::Rsa => signature.to_vec(),
        };

        let rc = unsafe {
            ffi::EVP_DigestVerify(
                self.evp_md_ctx.as_mut_ptr(),
                crypto_sig.as_ptr() as *mut std::os::raw::c_uchar,
                crypto_sig.len() as std::os::raw::c_ulong,
                data.as_ptr() as *mut std::os::raw::c_uchar,
                data.len() as std::os::raw::c_ulong,
            )
        };
        if rc != 1 {
            return Err(Error::DigestVerify);
        }
        Ok(())
    }

    fn verify_sig_len_ck(&self, sig_len_ck: usize) -> bool {
        // NOTE: With ECDSA, the PKCS#11 v2.40 Mechanisms Spec does allow for smaller
        //       signatures, obtained by only padding the lesser of R or S to the size of the
        //       greater one (as opposed to zero-padding both R and S to their maximum size).
        //       So this check should actualy be:
        //         (sig_len_ck & 1) == 0 && sig_len_ck <= self.sig_len_ck
        //       However, older versions of the spec, required full zero-padding, and v2.40
        //       suggests it as well. Our test suite enforces/expects full zero-padding, so
        //       for now, let's just go with the flow.
        sig_len_ck == self.sig_len_ck
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

impl DirectVerifyCtx {
    pub fn new(mech: &Mechanism, mut pkey: Pkey) -> Result<Self, Error> {
        let mut evp_pkey_ctx =
            FfiBox::new(unsafe { ffi::EVP_PKEY_CTX_new(pkey.as_mut_ptr(), std::ptr::null()) })
                .map_err(|_| Error::PkeyCtxInit)?;
        let rc = unsafe { ffi::EVP_PKEY_verify_init(evp_pkey_ctx.as_mut_ptr()) };
        if rc != 1 {
            return Err(Error::VerifyInit);
        }
        config_evp_pkey_ctx(evp_pkey_ctx.as_mut_ptr(), mech)?;

        Ok(Self {
            evp_pkey_ctx,
            algo: pkey.algo()?,
            sig_len_ck: pkey.sig_len_ck()?,
        })
    }
}

impl VerifyCtx for DirectVerifyCtx {
    fn verify(mut self: Box<Self>, data: &[u8], signature: &[u8]) -> Result<(), Error> {
        let crypto_sig = match self.algo {
            KeyAlgo::Ec => ecdsa_sig_ckrs_to_der(signature)?,
            KeyAlgo::Rsa => signature.to_vec(),
        };
        let rc = unsafe {
            ffi::EVP_PKEY_verify(
                self.evp_pkey_ctx.as_mut_ptr(),
                crypto_sig.as_ptr(),
                crypto_sig.len() as ffi::c_size_t,
                data.as_ptr(),
                data.len() as ffi::c_size_t,
            )
        };
        if rc != 1 {
            return Err(Error::DirectVerify);
        }
        Ok(())
    }

    fn verify_sig_len_ck(&self, sig_len_ck: usize) -> bool {
        // NOTE: With ECDSA, the PKCS#11 v2.40 Mechanisms Spec does allow for smaller
        //       signatures, obtained by only padding the lesser of R or S to the size of the
        //       greater one (as opposed to zero-padding both R and S to their maximum size).
        //       So this check should actualy be:
        //         (sig_len_ck & 1) == 0 && sig_len_ck <= self.sig_len_ck
        //       However, older versions of the spec, required full zero-padding, and v2.40
        //       suggests it as well. Our test suite enforces/expects full zero-padding, so
        //       for now, let's just go with the flow.
        sig_len_ck == self.sig_len_ck
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
    fn finalize(self: Box<Self>, _signature: &[u8]) -> Result<(), Error> {
        Err(Error::OperationActive)
    }
}
