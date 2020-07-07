use super::util::copy_data_to_ck_out_slice;
use crate::backend::Mechanism;
use crate::crypto::OpCtxState;
use crate::pkcs11;
use crate::util::ckraw::CkRawMechanism;
use crate::Error;

/// See PKCS#11 v2.40 Section 5.8 Encryption functions

pub extern "C" fn C_EncryptInit(
    hSession: pkcs11::CK_SESSION_HANDLE,
    pMechanism: pkcs11::CK_MECHANISM_PTR,
    hKey: pkcs11::CK_OBJECT_HANDLE,
) -> pkcs11::CK_RV {
    if pMechanism.is_null() {
        error!("C_EncryptInit() called with NULL mech");
        return pkcs11::CKR_ARGUMENTS_BAD;
    }

    lock_session_mut!(hSession, session, _sarc);

    let raw_mech = unsafe { CkRawMechanism::from_raw_ptr_unchecked(pMechanism) };
    let mech = match Mechanism::from_ckraw_mech(&raw_mech) {
        Ok(mech) => mech,
        Err(_) => return pkcs11::CKR_MECHANISM_INVALID,
    };

    session
        .encrypt_init(&mech, hKey.into())
        .map(|_| pkcs11::CKR_OK)
        .unwrap_or_else(|e| e.into())
}

pub extern "C" fn C_Encrypt(
    hSession: pkcs11::CK_SESSION_HANDLE,
    pData: pkcs11::CK_BYTE_PTR,
    ulDataLen: pkcs11::CK_ULONG,
    pEncryptedData: pkcs11::CK_BYTE_PTR,
    pulEncryptedDataLen: pkcs11::CK_ULONG_PTR,
) -> pkcs11::CK_RV {
    trace!("C_Encrypt() called");

    lock_session_mut!(hSession, session, _sarc);

    let out_len = match session
        .encrypt_ctx()
        .as_mut()
        .ok_or(Error::OperationNotInitialized)
        .and_then(|ctx| {
            ctx.enter_state(OpCtxState::SinglepartActive)
                .map_err(Error::CryptoError)?;
            Ok(ctx.len())
        }) {
        Ok(l) => l,
        Err(e) => {
            session.encrypt_ctx().take();
            return e.into();
        }
    };

    let out_slice = ck_out_buf_to_mut_slice!(pEncryptedData, pulEncryptedDataLen, out_len, {
        session.sign_ctx().take();
    });
    let in_slice = ck_in_buf_to_slice!(pData, ulDataLen, {
        session.sign_ctx().take();
    });

    session
        .encrypt_ctx()
        .take()
        // It's safe to unwrap here since we've already checked for an existing EncryptCtx
        .unwrap()
        .encrypt(in_slice)
        .map(|v| copy_data_to_ck_out_slice(v.as_slice(), out_slice, pulEncryptedDataLen))
        .map_err(Error::CryptoError)
        .unwrap_or_else(|e| e.into())
}
