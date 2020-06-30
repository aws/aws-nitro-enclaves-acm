use super::util::copy_data_to_ck_out_slice;
use crate::backend::Mechanism;
use crate::crypto::OpCtxState;
use crate::pkcs11;
use crate::util::ckraw::CkRawMechanism;
use crate::Error;

pub extern "C" fn C_DecryptInit(
    hSession: pkcs11::CK_SESSION_HANDLE,
    pMechanism: pkcs11::CK_MECHANISM_PTR,
    hKey: pkcs11::CK_OBJECT_HANDLE,
) -> pkcs11::CK_RV {
    trace!("C_DecryptInit() called");

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
        .decrypt_init(&mech, hKey.into())
        .map(|_| pkcs11::CKR_OK)
        .unwrap_or_else(|e| e.into())
}

pub extern "C" fn C_Decrypt(
    hSession: pkcs11::CK_SESSION_HANDLE,
    pEncryptedData: pkcs11::CK_BYTE_PTR,
    ulEncryptedDataLen: pkcs11::CK_ULONG,
    pData: pkcs11::CK_BYTE_PTR,
    pulDataLen: pkcs11::CK_ULONG_PTR,
) -> pkcs11::CK_RV {
    trace!("C_Decrypt() called");

    lock_session_mut!(hSession, session, _sarc);

    let out_len = match session
        .decrypt_ctx()
        .as_mut()
        .ok_or(Error::OperationNotInitialized)
        .and_then(|ctx| {
            ctx.enter_state(OpCtxState::SinglepartActive)
                .map_err(Error::CryptoError)?;
            Ok(ctx.len())
        }) {
        Ok(l) => l,
        Err(e) => {
            session.decrypt_ctx().take();
            return e.into();
        }
    };

    let out_slice = ck_out_buf_to_mut_slice!(pData, pulDataLen, out_len, {
        session.decrypt_ctx().take();
    });
    let in_slice = ck_in_buf_to_slice!(pEncryptedData, ulEncryptedDataLen, {
        session.decrypt_ctx().take();
    });

    session
        .decrypt_ctx()
        .take()
        // It's safe to unwrap here since we've already checked for an existing DecryptCtx
        .unwrap()
        .decrypt(in_slice)
        .map(|v| copy_data_to_ck_out_slice(v.as_slice(), out_slice, pulDataLen))
        .map_err(Error::CryptoError)
        .unwrap_or_else(|e| e.into())
}
