// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

mod ffi;

/// Number of bytes to seed
const DEV_SEED_CNT: usize = 512;

fn main() {
    let rc = unsafe { ffi::aws_nitro_enclaves_library_seed_entropy(DEV_SEED_CNT) };
    if rc == 0 {
        println!("[vToken] urand initialized via NSM");
        std::process::exit(0)
    } else {
        println!("[vToken] Cannot initialize urand via NSM");
        std::process::exit(1)
    }
}
