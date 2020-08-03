// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod ckraw;
pub mod logger;

pub use ckraw::{CkRawAttr, CkRawAttrTemplate, CkRawMechanism};

macro_rules! ck_padded_str {
    ($src:expr, $len: expr) => {{
        let mut ret = [b' '; $len];
        let count = std::cmp::min($src.len(), $len);
        ret[..count].copy_from_slice(&$src.as_bytes()[..count]);
        ret
    }};
}

macro_rules! ck_version {
    ($major:expr, $minor:expr) => {
        crate::pkcs11::CK_VERSION {
            major: $major,
            minor: $minor,
        }
    };
}

pub enum Error {
    BufTooSmall,
    MechParamTypeMismatch,
    NullPtrDeref,
}
