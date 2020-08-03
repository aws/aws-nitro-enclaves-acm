// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]

/// Utility macro for locking the vToken device
/// It creates two variables in the calling scope, one holding the lock guard
/// and the other a reference to the device.
macro_rules! lock_device {
    ($guard:ident, $device:ident) => {
        let $guard = crate::data::DEVICE.lock().unwrap();
        if $guard.is_none() {
            return crate::pkcs11::CKR_CRYPTOKI_NOT_INITIALIZED;
        }
        let $device = $guard.as_ref().unwrap();
    };
}

/// Utility macro for locking the vToken device
/// It creates two variables in the calling scope, one holding the lock guard
/// and the other a mutable reference to the device.
macro_rules! lock_device_mut {
    ($guard:ident, $device:ident) => {
        let mut $guard = crate::data::DEVICE.lock().unwrap();
        if $guard.is_none() {
            return crate::pkcs11::CKR_CRYPTOKI_NOT_INITIALIZED;
        }
        let $device = $guard.as_mut().unwrap();
    };
}

/// Utility macro for locking a vToken session
/// It creates two variables in the calling scope, one holding the lock guard
/// and the other a reference to the session.
macro_rules! lock_session {
    ($handle:expr, $session:ident, $sess_arc:ident) => {
        let $sess_arc;
        let $session;
        {
            lock_device!(guard, device);
            $sess_arc = device.session($handle);
            $session = match $sess_arc {
                Some(ref sess) => sess.lock().unwrap(),
                None => return crate::pkcs11::CKR_SESSION_HANDLE_INVALID,
            };
        }
    };
}

/// Utility macro for locking a vToken session
/// It creates two variables in the calling scope, one holding the lock guard
/// and the other a mutable reference to the session.
macro_rules! lock_session_mut {
    ($handle:expr, $session:ident, $sess_arc:ident) => {
        let $sess_arc;
        let mut $session;
        {
            lock_device!(guard, device);
            $sess_arc = device.session($handle);
            $session = match $sess_arc {
                Some(ref sess) => sess.lock().unwrap(),
                None => return crate::pkcs11::CKR_SESSION_HANDLE_INVALID,
            };
        }
    };
}

/// Utility macro implementing the PKCS#11 Section 5.2 on producing output
/// for serveral API functions
macro_rules! ck_out_buf_to_mut_slice {
    ($buf_ptr:ident, $buf_len_ptr:ident, $min_len:expr, $on_err:block) => {{
        if $buf_len_ptr.is_null() {
            $on_err;
            return crate::pkcs11::CKR_ARGUMENTS_BAD;
        }
        let user_len = unsafe { std::ptr::read($buf_len_ptr) };
        unsafe {
            std::ptr::write($buf_len_ptr, $min_len as pkcs11::CK_ULONG);
        }
        if $buf_ptr.is_null() {
            return crate::pkcs11::CKR_OK;
        }
        if user_len < $min_len as pkcs11::CK_ULONG {
            return crate::pkcs11::CKR_BUFFER_TOO_SMALL;
        }
        unsafe { std::slice::from_raw_parts_mut($buf_ptr, user_len as usize) }
    }};
}

/// Utility macro for passing raw foreign pointers to slices passed
/// to the module backends
macro_rules! ck_in_buf_to_slice {
    ($buf_ptr:ident, $buf_len_ptr:ident, $on_err:block) => {{
        if $buf_ptr.is_null() {
            $on_err;
            return pkcs11::CKR_ARGUMENTS_BAD;
        }
        unsafe { std::slice::from_raw_parts($buf_ptr, $buf_len_ptr as usize) }
    }};
}

pub mod util {
    use crate::pkcs11;
    use std::ptr;

    pub fn copy_data_to_ck_out_slice(
        src: &[u8],
        dst: &mut [u8],
        dst_len_ptr: *mut pkcs11::CK_ULONG,
    ) -> pkcs11::CK_RV {
        if dst.len() < src.len() {
            // This should never happen, as the output slice should've already been constucted
            // from a validated buffer. If it does, something must be terribly wrong.
            pkcs11::CKR_DEVICE_ERROR
        } else {
            dst[..src.len()].copy_from_slice(src);
            unsafe {
                ptr::write(dst_len_ptr, src.len() as pkcs11::CK_ULONG);
            }
            pkcs11::CKR_OK
        }
    }
}

pub mod decrypt;
pub mod digest;
pub mod encrypt;
pub mod nyi;
pub mod object;
pub mod session;
pub mod sign;
pub mod token;
pub mod verify;

use crate::backend::device::Device;
use crate::data;
use crate::defs;
use crate::pkcs11;
use crate::util::logger::Logger;

/// See PKCS#11 v2.40 Section 5.4 General-purpose functions
#[no_mangle]
pub extern "C" fn C_GetFunctionList(
    pp_fn_list: *mut *const pkcs11::CK_FUNCTION_LIST,
) -> pkcs11::CK_RV {
    if pp_fn_list.is_null() {
        return pkcs11::CKR_ARGUMENTS_BAD;
    }

    unsafe {
        std::ptr::write(pp_fn_list, &data::FN_LIST);
    }
    pkcs11::CKR_OK
}

pub extern "C" fn C_Initialize(pInitArgs: pkcs11::CK_VOID_PTR) -> pkcs11::CK_RV {
    // TODO: implement a proper logger, so we
    // don't have to hack this piggybacking on top of C_Initialize.
    Logger::init();

    trace!("C_Initialize() called");

    if defs::CRYPTOKI_VERSION == ck_version!(2, 40) && !pInitArgs.is_null() {
        let args = pInitArgs as pkcs11::CK_C_INITIALIZE_ARGS_PTR;
        unsafe {
            if !(*args).pReserved.is_null() {
                return pkcs11::CKR_ARGUMENTS_BAD;
            }
        }
    }
    let mut maybe_device = data::DEVICE.lock().unwrap();
    if maybe_device.is_some() {
        return pkcs11::CKR_CRYPTOKI_ALREADY_INITIALIZED;
    }
    maybe_device.replace(Device::new());
    pkcs11::CKR_OK
}

pub extern "C" fn C_Finalize(pReserved: pkcs11::CK_VOID_PTR) -> pkcs11::CK_RV {
    trace!("C_Finalize() called");

    if defs::CRYPTOKI_VERSION == ck_version!(2, 40) && !pReserved.is_null() {
        return pkcs11::CKR_ARGUMENTS_BAD;
    }

    let mut maybe_device = data::DEVICE.lock().unwrap();
    if maybe_device.is_none() {
        pkcs11::CKR_CRYPTOKI_NOT_INITIALIZED
    } else {
        maybe_device.take();
        pkcs11::CKR_OK
    }
}

pub extern "C" fn C_GetInfo(info: pkcs11::CK_INFO_PTR) -> pkcs11::CK_RV {
    trace!("C_GetInfo() called");

    if info.is_null() {
        error!("C_GetInfo() received NULL pointer.");
        return pkcs11::CKR_ARGUMENTS_BAD;
    }

    lock_device!(guard, device);
    unsafe {
        std::ptr::write(info, device.ck_info());
    }
    pkcs11::CKR_OK
}
