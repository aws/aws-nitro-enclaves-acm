use crate::pkcs11;

/// See PKCS#11 v2.40 Section 5.6 Session management functions

pub extern "C" fn C_OpenSession(
    slotID: pkcs11::CK_SLOT_ID,
    flags: pkcs11::CK_FLAGS,
    _pApplication: pkcs11::CK_VOID_PTR,
    _Notify: pkcs11::CK_NOTIFY,
    phSession: pkcs11::CK_SESSION_HANDLE_PTR,
) -> pkcs11::CK_RV {
    trace!("C_OpenSession() called");

    if phSession.is_null() {
        error!("C_OpenSession() called with NULL output ptr.");
        return pkcs11::CKR_ARGUMENTS_BAD;
    }
    if flags & pkcs11::CKF_SERIAL_SESSION == 0 {
        error!("C_OpenSession() legacy serialization flag must be set.");
        return pkcs11::CKR_SESSION_PARALLEL_NOT_SUPPORTED;
    }
    if flags & pkcs11::CKF_RW_SESSION != 0 {
        error!("C_OpenSession() R/W sessions are not supported");
        return pkcs11::CKR_TOKEN_WRITE_PROTECTED;
    }

    lock_device_mut!(guard, device);

    device
        .open_session(slotID)
        .and_then(|handle| {
            unsafe {
                std::ptr::write(phSession, handle);
            }
            Ok(())
        })
        .map(|_| pkcs11::CKR_OK)
        .unwrap_or_else(|e| e.into())
}

pub extern "C" fn C_CloseSession(hSession: pkcs11::CK_SESSION_HANDLE) -> pkcs11::CK_RV {
    trace!("C_CloseSession() called");
    lock_device_mut!(guard, device);

    device
        .close_session(hSession)
        .map(|_| pkcs11::CKR_OK)
        .unwrap_or_else(|e| e.into())
}

pub extern "C" fn C_CloseAllSessions(slotID: pkcs11::CK_SLOT_ID) -> pkcs11::CK_RV {
    trace!("C_CloseAllSessions() called");
    lock_device_mut!(guard, device);

    device
        .close_all_slot_sessions(slotID)
        .map(|_| pkcs11::CKR_OK)
        .unwrap_or_else(|e| e.into())
}

pub extern "C" fn C_GetSessionInfo(
    hSession: pkcs11::CK_SESSION_HANDLE,
    pInfo: pkcs11::CK_SESSION_INFO_PTR,
) -> pkcs11::CK_RV {
    trace!("C_GetSessionInfo() called");

    if pInfo.is_null() {
        return pkcs11::CKR_ARGUMENTS_BAD;
    }
    lock_session!(hSession, session, _sess_arc);

    // Already checked for NULL ptr.
    let ck_info = session.ck_info();
    unsafe {
        std::ptr::write(pInfo, ck_info);
    }

    pkcs11::CKR_OK
}

pub extern "C" fn C_GetFunctionStatus(hSession: pkcs11::CK_SESSION_HANDLE) -> pkcs11::CK_RV {
    trace!("C_GetFunctionStatus() called");
    lock_session!(hSession, _session, _sess_arc);
    pkcs11::CKR_FUNCTION_NOT_PARALLEL
}

pub extern "C" fn C_CancelFunction(hSession: pkcs11::CK_SESSION_HANDLE) -> pkcs11::CK_RV {
    trace!("C_CancelFunction() called");
    lock_session!(hSession, _session, _sess_arc);
    pkcs11::CKR_FUNCTION_NOT_PARALLEL
}
