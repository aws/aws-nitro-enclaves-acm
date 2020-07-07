use crate::backend::Mechanism;
use crate::crypto::OpCtxState;
use crate::pkcs11;
use crate::util::ckraw::CkRawMechanism;
use crate::Error;

/// See PKCS#11 v2.40 5.11 Signing and MACing functions

pub extern "C" fn C_VerifyInit(
    hSession: pkcs11::CK_SESSION_HANDLE,
    pMechanism: pkcs11::CK_MECHANISM_PTR,
    hKey: pkcs11::CK_OBJECT_HANDLE,
) -> pkcs11::CK_RV {
    trace!("C_VerifyInit() called");

    if pMechanism.is_null() {
        return pkcs11::CKR_ARGUMENTS_BAD;
    }

    let raw_mech = unsafe { CkRawMechanism::from_raw_ptr_unchecked(pMechanism) };
    let mech = match Mechanism::from_ckraw_mech(&raw_mech) {
        Ok(mech) => mech,
        Err(_) => return pkcs11::CKR_MECHANISM_INVALID,
    };

    lock_session_mut!(hSession, session, _sarc);

    session
        .verify_init(&mech, hKey.into())
        .map(|_| pkcs11::CKR_OK)
        .unwrap_or_else(|e| e.into())
}

pub extern "C" fn C_Verify(
    hSession: pkcs11::CK_SESSION_HANDLE,
    pData: pkcs11::CK_BYTE_PTR,
    ulDataLen: pkcs11::CK_ULONG,
    pSignature: pkcs11::CK_BYTE_PTR,
    ulSignatureLen: pkcs11::CK_ULONG,
) -> pkcs11::CK_RV {
    trace!("C_Verify() called");

    lock_session_mut!(hSession, session, _sarc);

    let ctx = match session.verify_ctx().take() {
        Some(mut ctx) => {
            if let Err(e) = ctx.enter_state(OpCtxState::SinglepartActive) {
                return Error::CryptoError(e).into();
            }
            ctx
        }
        None => return pkcs11::CKR_OPERATION_NOT_INITIALIZED,
    };
    let data_slice = ck_in_buf_to_slice!(pData, ulDataLen, {});
    let sig_slice = ck_in_buf_to_slice!(pSignature, ulSignatureLen, {});

    if !ctx.verify_sig_len_ck(sig_slice.len()) {
        return pkcs11::CKR_SIGNATURE_LEN_RANGE;
    }

    ctx.verify(data_slice, sig_slice)
        .map(|_| pkcs11::CKR_OK)
        .map_err(Error::CryptoError)
        .unwrap_or_else(|e| e.into())
}

pub extern "C" fn C_VerifyUpdate(
    hSession: pkcs11::CK_SESSION_HANDLE,
    pPart: pkcs11::CK_BYTE_PTR,
    ulPartLen: pkcs11::CK_ULONG,
) -> pkcs11::CK_RV {
    trace!("C_VerifyUpdate() called");

    lock_session_mut!(hSession, session, _sarc);

    let data_slice = ck_in_buf_to_slice!(pPart, ulPartLen, {});
    session
        .verify_ctx()
        .as_mut()
        .ok_or(Error::OperationNotInitialized)
        .and_then(|ctx| ctx.update(data_slice).map_err(Error::CryptoError))
        .map(|_| pkcs11::CKR_OK)
        .unwrap_or_else(|e| e.into())
}

pub extern "C" fn C_VerifyFinal(
    hSession: pkcs11::CK_SESSION_HANDLE,
    pSignature: pkcs11::CK_BYTE_PTR,
    ulSignatureLen: pkcs11::CK_ULONG,
) -> pkcs11::CK_RV {
    trace!("C_VerifyFinal() called");

    lock_session_mut!(hSession, session, _sarc);

    let ctx = match session.verify_ctx().take() {
        Some(mut ctx) => {
            if let Err(e) = ctx.enter_state(OpCtxState::MultipartReady) {
                return Error::CryptoError(e).into();
            }
            ctx
        }
        None => return pkcs11::CKR_OPERATION_NOT_INITIALIZED,
    };
    let sig_slice = ck_in_buf_to_slice!(pSignature, ulSignatureLen, {});

    if !ctx.verify_sig_len_ck(sig_slice.len()) {
        return pkcs11::CKR_SIGNATURE_LEN_RANGE;
    }

    ctx.finalize(sig_slice)
        .map_err(Error::CryptoError)
        .map(|_| pkcs11::CKR_OK)
        .unwrap_or_else(|e| e.into())
}
