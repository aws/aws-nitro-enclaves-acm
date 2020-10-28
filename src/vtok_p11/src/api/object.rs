// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::pkcs11;
use crate::util::CkRawAttrTemplate;
use std::ptr;

/// See PKCS#11 v2.40 Section 5.7 Object management functions

pub extern "C" fn C_FindObjectsInit(
    hSession: pkcs11::CK_SESSION_HANDLE,
    pTemplate: pkcs11::CK_ATTRIBUTE_PTR,
    ulCount: pkcs11::CK_ULONG,
) -> pkcs11::CK_RV {
    trace!("C_FindObjectsInit() called");

    if ulCount > 0 && pTemplate.is_null() {
        error!("C_FindObjectsInit() called with non-zero count and NULL template");
        return pkcs11::CKR_ARGUMENTS_BAD;
    }

    lock_session_mut!(hSession, session, _sess_arc);

    if session.enum_active() {
        return pkcs11::CKR_OPERATION_ACTIVE;
    }

    let attr_template = if !pTemplate.is_null() {
        Some(unsafe { CkRawAttrTemplate::from_raw_ptr_unchecked(pTemplate, ulCount as usize) })
    } else {
        None
    };
    session.enum_init(attr_template);

    pkcs11::CKR_OK
}

pub extern "C" fn C_FindObjects(
    hSession: pkcs11::CK_SESSION_HANDLE,
    phObject: pkcs11::CK_OBJECT_HANDLE_PTR,
    ulMaxObjectCount: pkcs11::CK_ULONG,
    pulObjectCount: pkcs11::CK_ULONG_PTR,
) -> pkcs11::CK_RV {
    trace!("C_FindObjects() called");

    if phObject.is_null() || pulObjectCount.is_null() {
        error!("C_FindObects(): NULL output pointer provided.");
        return pkcs11::CKR_ARGUMENTS_BAD;
    }
    lock_session_mut!(hSession, session, _sess_arc);

    if !session.enum_active() {
        return pkcs11::CKR_OPERATION_NOT_INITIALIZED;
    }

    match session.enum_next_chunk(ulMaxObjectCount as usize) {
        Some(chunk) => {
            info!("C_FindObjects returning count={}", chunk.len());
            for (i, _obj) in chunk.iter().enumerate() {
                unsafe {
                    ptr::write(phObject.add(i), chunk[i].into());
                };
            }
            unsafe {
                ptr::write(pulObjectCount, chunk.len() as pkcs11::CK_ULONG);
            };
        }
        None => {
            // Enumeration context consumed
            unsafe {
                ptr::write(pulObjectCount, 0 as pkcs11::CK_ULONG);
            }
        }
    }
    pkcs11::CKR_OK
}

pub extern "C" fn C_FindObjectsFinal(hSession: pkcs11::CK_SESSION_HANDLE) -> pkcs11::CK_RV {
    trace!("C_FindObjectsFinal() called");

    lock_session_mut!(hSession, session, _sess_arc);

    session
        .enum_finalize()
        .map(|_| pkcs11::CKR_OK)
        .unwrap_or_else(|e| e.into())
}

pub extern "C" fn C_GetAttributeValue(
    hSession: pkcs11::CK_SESSION_HANDLE,
    hObject: pkcs11::CK_OBJECT_HANDLE,
    pTemplate: pkcs11::CK_ATTRIBUTE_PTR,
    ulCount: pkcs11::CK_ULONG,
) -> pkcs11::CK_RV {
    trace!("C_GetAttributeValue() called, count={}", ulCount);
    if pTemplate.is_null() {
        error!("C_GetAttributeValue() called with NULL output ptr");
        return pkcs11::CKR_ARGUMENTS_BAD;
    }

    lock_session!(hSession, session, _sarc);
    let obj = match session.object(hObject.into()) {
        Some(obj) => obj,
        None => return pkcs11::CKR_OBJECT_HANDLE_INVALID,
    };

    // Already checked for null
    let mut attr_tmpl =
        unsafe { CkRawAttrTemplate::from_raw_ptr_unchecked(pTemplate, ulCount as usize) };

    obj.fill_attr_template(&mut attr_tmpl)
        .map(|_| pkcs11::CKR_OK)
        .unwrap_or_else(|e| e.into())
}

pub extern "C" fn C_GetObjectSize(
    hSession: pkcs11::CK_SESSION_HANDLE,
    hObject: pkcs11::CK_OBJECT_HANDLE,
    pulSize: pkcs11::CK_ULONG_PTR,
) -> pkcs11::CK_RV {
    trace!("C_GetObjectSize() called");

    if pulSize.is_null() {
        return pkcs11::CKR_ARGUMENTS_BAD;
    }

    lock_session!(hSession, session, _src);

    if session.object(hObject.into()).is_some() {
        // The tokens do not export memory consumption info
        // thus neither token objects should. We just implement this
        // function for standard compliance and testing.
        unsafe {
            ptr::write(
                pulSize,
                pkcs11::CK_UNAVAILABLE_INFORMATION as pkcs11::CK_ULONG,
            );
        }
        return pkcs11::CKR_OK;
    }
    pkcs11::CKR_OBJECT_HANDLE_INVALID
}
