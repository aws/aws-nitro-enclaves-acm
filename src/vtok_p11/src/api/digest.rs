// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::util::copy_data_to_ck_out_slice;
use crate::crypto::OpCtxState;
use crate::pkcs11;
use crate::Error;

/// See PKCS#11 v2.40 Section 5.10 Message digesting functions

pub extern "C" fn C_DigestInit(
    hSession: pkcs11::CK_SESSION_HANDLE,
    pMechanism: *mut pkcs11::CK_MECHANISM,
) -> pkcs11::CK_RV {
    trace!("C_DigestInit() called");

    if pMechanism.is_null() {
        error!("C_DigestInit() called with NULL mech ptr");
        return pkcs11::CKR_ARGUMENTS_BAD;
    }
    let mech_type = unsafe { (*pMechanism).mechanism };

    lock_session_mut!(hSession, session, _sarc);
    session
        .digest_init(mech_type)
        .map(|_| pkcs11::CKR_OK)
        .unwrap_or_else(|e| e.into())
}

pub extern "C" fn C_Digest(
    hSession: pkcs11::CK_SESSION_HANDLE,
    pData: *mut pkcs11::CK_BYTE,
    ulDataLen: pkcs11::CK_ULONG,
    pDigest: *mut pkcs11::CK_BYTE,
    pulDigestLen: *mut pkcs11::CK_ULONG,
) -> pkcs11::CK_RV {
    trace!("C_Digest() called");

    lock_session_mut!(hSession, session, _sarc);

    let out_len = match session
        .digest_ctx()
        .as_mut()
        .ok_or(Error::OperationNotInitialized)
        .and_then(|ctx| {
            ctx.enter_state(OpCtxState::SinglepartActive)
                .map_err(Error::CryptoError)?;
            Ok(ctx.len())
        }) {
        Ok(l) => l,
        Err(e) => {
            session.digest_ctx().take();
            return e.into();
        }
    };

    let out_slice = ck_out_buf_to_mut_slice!(pDigest, pulDigestLen, out_len, {
        session.digest_ctx().take()
    });
    let in_slice = ck_in_buf_to_slice!(pData, ulDataLen, {
        session.digest_ctx().take();
    });

    session
        .digest_ctx()
        .take()
        // It's safe to unwrap here since we've already checked for a digest ctx.
        .unwrap()
        .digest(in_slice)
        .map(|v| copy_data_to_ck_out_slice(v.as_slice(), out_slice, pulDigestLen))
        .map_err(Error::CryptoError)
        .unwrap_or_else(|e| e.into())
}

pub extern "C" fn C_DigestUpdate(
    hSession: pkcs11::CK_SESSION_HANDLE,
    pPart: *mut pkcs11::CK_BYTE,
    ulPartLen: pkcs11::CK_ULONG,
) -> pkcs11::CK_RV {
    trace!("C_DigestUpdate() called");

    lock_session_mut!(hSession, session, _sarc);
    let in_slice = ck_in_buf_to_slice!(pPart, ulPartLen, {
        session.digest_ctx().take();
    });
    session
        .digest_ctx()
        .as_mut()
        .ok_or(Error::OperationNotInitialized)
        .and_then(|ctx| ctx.update(in_slice).map_err(Error::CryptoError))
        .map(|_| pkcs11::CKR_OK)
        .unwrap_or_else(|e| e.into())
}

pub extern "C" fn C_DigestFinal(
    hSession: pkcs11::CK_SESSION_HANDLE,
    pDigest: *mut pkcs11::CK_BYTE,
    pulDigestLen: *mut pkcs11::CK_ULONG,
) -> pkcs11::CK_RV {
    trace!("C_DigestFinal() called");

    lock_session_mut!(hSession, session, _sarc);

    let out_len = match session
        .digest_ctx()
        .as_mut()
        .ok_or(Error::OperationNotInitialized)
        .and_then(|ctx| {
            ctx.enter_state(OpCtxState::MultipartReady)
                .map_err(Error::CryptoError)?;
            Ok(ctx.len())
        }) {
        Ok(l) => l,
        Err(e) => {
            session.digest_ctx().take();
            return e.into();
        }
    };

    let out_slice = ck_out_buf_to_mut_slice!(pDigest, pulDigestLen, out_len, {
        session.digest_ctx().take()
    });

    session
        .digest_ctx()
        .take()
        // It's safe to unwrap here since we've already checked for a digest ctx.
        .unwrap()
        .finalize()
        .map(|v| copy_data_to_ck_out_slice(v.as_slice(), out_slice, pulDigestLen))
        .map_err(Error::CryptoError)
        .unwrap_or_else(|e| e.into())
}
