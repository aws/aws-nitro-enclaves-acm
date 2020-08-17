// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

use std::os::raw::c_int;

/// Imported SDK APIs
extern "C" {
    pub fn aws_nitro_enclaves_library_seed_entropy(bytes: usize) -> c_int;
}
