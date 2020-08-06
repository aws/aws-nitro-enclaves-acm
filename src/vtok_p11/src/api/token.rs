// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::pkcs11;
use crate::Error;

/// See PKCS#11 v2.40 Section 5.5 Slot and token management functions

pub extern "C" fn C_GetSlotList(
    tokenPresent: pkcs11::CK_BBOOL,
    pSlotList: pkcs11::CK_SLOT_ID_PTR,
    pulCount: pkcs11::CK_ULONG_PTR,
) -> pkcs11::CK_RV {
    trace!("C_GetSlotList() called.");

    lock_device!(guard, device);

    if pulCount.is_null() {
        error!("C_GetSlotList() called with NULL count");
        return pkcs11::CKR_ARGUMENTS_BAD;
    }

    // Get the current slot count
    let slot_count = device.slot_count(tokenPresent != 0);

    if pSlotList.is_null() {
        unsafe {
            // Already checked for NULL.
            std::ptr::write(pulCount, slot_count as pkcs11::CK_ULONG);
        }
        return pkcs11::CKR_OK;
    } else {
        // Valid slot list - check if it has enough space
        unsafe {
            // Already checked for NULL.
            let in_count = std::ptr::read(pulCount);
            if in_count < (slot_count as pkcs11::CK_ULONG) {
                std::ptr::write(pulCount, slot_count as pkcs11::CK_ULONG);
                return pkcs11::CKR_BUFFER_TOO_SMALL;
            }
        }
    }

    let slot_id_vec = device.ck_slot_ids(tokenPresent != 0);

    // As safe as we can, since this buffer is managed by the lib user, and we've already
    // checked for NULL and avail size.
    unsafe {
        std::ptr::copy_nonoverlapping(slot_id_vec.as_ptr(), pSlotList, slot_id_vec.len());
        std::ptr::write(pulCount, slot_count as pkcs11::CK_ULONG);
    }

    pkcs11::CKR_OK
}

pub extern "C" fn C_GetSlotInfo(
    slotID: pkcs11::CK_SLOT_ID,
    pInfo: pkcs11::CK_SLOT_INFO_PTR,
) -> pkcs11::CK_RV {
    trace!("C_GetSlotInfo() called: slotID={}", slotID);

    lock_device!(guard, device);

    if pInfo.is_null() {
        error!("C_GetSlotInfo() called with NULL info");
        return pkcs11::CKR_ARGUMENTS_BAD;
    }

    device
        .slot(slotID)
        .ok_or(Error::SlotIdInvalid)
        .and_then(|slot| {
            let ck_info = slot.ck_info();
            unsafe {
                std::ptr::write(pInfo, ck_info);
            }
            Ok(pkcs11::CKR_OK)
        })
        .unwrap_or_else(|e| e.into())
}

pub extern "C" fn C_GetTokenInfo(
    slotID: pkcs11::CK_SLOT_ID,
    pInfo: *mut pkcs11::CK_TOKEN_INFO,
) -> pkcs11::CK_RV {
    trace!("C_GetTokenInfo() called: slotID={}", slotID);

    lock_device!(guard, device);

    if pInfo.is_null() {
        error!("C_GetTokenInfo() called with NULL OUTPUT pointer.");
        return pkcs11::CKR_ARGUMENTS_BAD;
    }

    device
        .token(slotID)
        .and_then(|token| {
            let ck_info = token.ck_info();
            unsafe {
                std::ptr::write(pInfo, ck_info);
            }
            Ok(pkcs11::CKR_OK)
        })
        .unwrap_or_else(|e| e.into())
}

pub extern "C" fn C_InitToken(
    _slotID: pkcs11::CK_SLOT_ID,
    _pPin: *mut pkcs11::CK_UTF8CHAR,
    _ulPinLen: pkcs11::CK_ULONG,
    _pLabel: *mut pkcs11::CK_UTF8CHAR,
) -> pkcs11::CK_RV {
    pkcs11::CKR_FUNCTION_NOT_SUPPORTED
}

pub extern "C" fn C_GetMechanismList(
    slotID: pkcs11::CK_SLOT_ID,
    pMechanismList: pkcs11::CK_MECHANISM_TYPE_PTR,
    pulCount: pkcs11::CK_ULONG_PTR,
) -> pkcs11::CK_RV {
    trace!("C_GetMechanismList() called");

    if pulCount.is_null() {
        error!("C_GetMechanismList called with NULL count");
        return pkcs11::CKR_ARGUMENTS_BAD;
    }

    lock_device!(guard, device);

    let mech_count = match device
        .token(slotID)
        .and_then(|tok| tok.mech_count().map_err(Error::TokenError))
    {
        Ok(count) => count,
        Err(e) => return e.into(),
    };

    if pMechanismList.is_null() {
        // Already checked for NULL.
        unsafe {
            std::ptr::write(pulCount, mech_count as pkcs11::CK_ULONG);
        }
        return pkcs11::CKR_OK;
    }

    // Already checked for NULL.
    let in_count = unsafe { std::ptr::read(pulCount) };

    // *pulCount needs to be set to the correct value, even if we aren't able to fill
    // in pMechanismList.
    unsafe {
        std::ptr::write(pulCount, mech_count as pkcs11::CK_ULONG);
    }

    // Check if the user provided a large enough buffer.
    if in_count < (mech_count as pkcs11::CK_ULONG) {
        return pkcs11::CKR_BUFFER_TOO_SMALL;
    }

    device
        .token(slotID)
        .and_then(|tok| tok.mech_list().map_err(Error::TokenError))
        .and_then(|mechs| {
            for (i, mk) in mechs.iter().enumerate() {
                unsafe {
                    std::ptr::write(pMechanismList.add(i), mk.ck_type());
                }
            }
            Ok(pkcs11::CKR_OK)
        })
        .unwrap_or_else(|e| e.into())
}

pub extern "C" fn C_GetMechanismInfo(
    slotID: pkcs11::CK_SLOT_ID,
    type_: pkcs11::CK_MECHANISM_TYPE,
    pInfo: pkcs11::CK_MECHANISM_INFO_PTR,
) -> pkcs11::CK_RV {
    trace!("C_GetMechanismInfo() called");

    if pInfo.is_null() {
        error!("C_GetMechanismInfo() called with NULL info");
        return pkcs11::CKR_ARGUMENTS_BAD;
    }

    lock_device!(guard, device);

    device
        .token(slotID)
        .and_then(|tok| tok.mech(type_).map_err(Error::TokenError))
        .and_then(|mech| {
            let mech_info = mech.ck_info();
            unsafe {
                std::ptr::write(pInfo, mech_info);
            }
            Ok(pkcs11::CKR_OK)
        })
        .unwrap_or_else(|e| e.into())
}

pub extern "C" fn C_Login(
    hSession: pkcs11::CK_SESSION_HANDLE,
    userType: pkcs11::CK_USER_TYPE,
    pPin: pkcs11::CK_UTF8CHAR_PTR,
    ulPinLen: pkcs11::CK_ULONG,
) -> pkcs11::CK_RV {
    trace!("C_Login() called");

    if pPin.is_null() {
        return pkcs11::CKR_ARGUMENTS_BAD;
    }

    lock_device_mut!(guard, device);

    match userType {
        pkcs11::CKU_SO => pkcs11::CKR_SESSION_READ_ONLY_EXISTS,
        pkcs11::CKU_CONTEXT_SPECIFIC => pkcs11::CKR_USER_TYPE_INVALID,
        pkcs11::CKU_USER => {
            // Already checked pPin for NULL.
            let pin_slice = unsafe { std::slice::from_raw_parts(pPin, ulPinLen as usize) };
            let pin = match std::str::from_utf8(pin_slice) {
                Ok(pin) => pin,
                Err(_) => return pkcs11::CKR_PIN_INCORRECT,
            };
            device
                .login(hSession, pin)
                .map(|_| pkcs11::CKR_OK)
                .unwrap_or_else(|e| e.into())
        }
        _ => pkcs11::CKR_USER_TYPE_INVALID,
    }
}

pub extern "C" fn C_Logout(hSession: pkcs11::CK_SESSION_HANDLE) -> pkcs11::CK_RV {
    trace!("C_Logout() called");

    lock_device_mut!(guard, device);

    device
        .logout(hSession)
        .map(|_| pkcs11::CKR_OK)
        .unwrap_or_else(|e| e.into())
}
