use super::util::copy_data_to_ck_out_slice;
use crate::backend::Mechanism;
use crate::crypto::OpCtxState;
use crate::pkcs11;
use crate::util::ckraw::CkRawMechanism;
use crate::Error;

pub extern "C" fn C_SignInit(
    hSession: pkcs11::CK_SESSION_HANDLE,
    pMechanism: *mut pkcs11::CK_MECHANISM,
    hKey: pkcs11::CK_OBJECT_HANDLE,
) -> pkcs11::CK_RV {
    trace!("C_SignInit() called");

    if pMechanism.is_null() {
        error!("C_SignInit() called with NULL mech");
        return pkcs11::CKR_ARGUMENTS_BAD;
    }
    let raw_mech = unsafe { CkRawMechanism::from_raw_ptr_unchecked(pMechanism) };
    let mech = match Mechanism::from_ckraw_mech(&raw_mech) {
        Ok(mech) => mech,
        Err(_) => return pkcs11::CKR_MECHANISM_INVALID,
    };

    lock_session_mut!(hSession, session, _sarc);
    session
        .sign_init(&mech, hKey.into())
        .map(|_| pkcs11::CKR_OK)
        .unwrap_or_else(|e| e.into())
}

pub extern "C" fn C_Sign(
    hSession: pkcs11::CK_SESSION_HANDLE,
    pData: *mut pkcs11::CK_BYTE,
    ulDataLen: pkcs11::CK_ULONG,
    pSignature: *mut pkcs11::CK_BYTE,
    pulSignatureLen: *mut pkcs11::CK_ULONG,
) -> pkcs11::CK_RV {
    trace!("C_Sign() called");

    lock_session_mut!(hSession, session, _sarc);

    let out_len = match session
        .sign_ctx()
        .as_mut()
        .ok_or(Error::OperationNotInitialized)
        .and_then(|ctx| {
            ctx.enter_state(OpCtxState::SinglepartActive)
                .map_err(Error::CryptoError)?;
            Ok(ctx.sig_len_ck())
        }) {
        Ok(l) => l,
        Err(e) => {
            session.sign_ctx().take();
            return e.into();
        }
    };

    let out_slice = ck_out_buf_to_mut_slice!(pSignature, pulSignatureLen, out_len, {
        session.sign_ctx().take();
    });
    let in_slice = ck_in_buf_to_slice!(pData, ulDataLen, {
        session.sign_ctx().take();
    });

    session
        .sign_ctx()
        .take()
        // It's safe to unwrap here since we've already checked for a sign ctx.
        .unwrap()
        .sign(in_slice)
        .map(|v| copy_data_to_ck_out_slice(v.as_slice(), out_slice, pulSignatureLen))
        .map_err(Error::CryptoError)
        .unwrap_or_else(|e| e.into())
}

pub extern "C" fn C_SignUpdate(
    hSession: pkcs11::CK_SESSION_HANDLE,
    pPart: *mut pkcs11::CK_BYTE,
    ulPartLen: pkcs11::CK_ULONG,
) -> pkcs11::CK_RV {
    trace!("C_SignUpdate() called");
    if pPart.is_null() {
        error!("C_SignUpdate() called with null data ptr.");
        return pkcs11::CKR_ARGUMENTS_BAD;
    }

    lock_session_mut!(hSession, session, _sarc);
    let in_slice = ck_in_buf_to_slice!(pPart, ulPartLen, {
        session.sign_ctx().take();
    });
    session
        .sign_ctx()
        .take()
        .as_mut()
        .ok_or(Error::OperationNotInitialized)
        .and_then(|ctx| ctx.update(in_slice).map_err(Error::CryptoError))
        .map(|_| pkcs11::CKR_OK)
        .unwrap_or_else(|e| e.into())
}

pub extern "C" fn C_SignFinal(
    hSession: pkcs11::CK_SESSION_HANDLE,
    pSignature: *mut pkcs11::CK_BYTE,
    pulSignatureLen: *mut pkcs11::CK_ULONG,
) -> pkcs11::CK_RV {
    trace!("C_SignFinal() called");

    lock_session_mut!(hSession, session, _sarc);

    let out_len = match session
        .sign_ctx()
        .as_mut()
        .ok_or(Error::OperationNotInitialized)
        .and_then(|ctx| {
            ctx.enter_state(OpCtxState::MultipartReady)
                .map_err(Error::CryptoError)?;
            Ok(ctx.sig_len_ck())
        }) {
        Ok(l) => l,
        Err(e) => {
            session.sign_ctx().take();
            return e.into();
        }
    };
    let out_slice = ck_out_buf_to_mut_slice!(pSignature, pulSignatureLen, out_len, {
        session.sign_ctx().take();
    });

    session
        .sign_ctx()
        .take()
        // It's safe to unwrap here since we've already checked for a sign ctx.
        .unwrap()
        .finalize()
        .map(|v| copy_data_to_ck_out_slice(v.as_slice(), out_slice, pulSignatureLen))
        .map_err(Error::CryptoError)
        .unwrap_or_else(|e| e.into())
}
