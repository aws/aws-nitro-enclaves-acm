// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

fn main() {
    println!("cargo:rustc-link-lib=dylib=aws-c-common");
    println!("cargo:rustc-link-lib=dylib=aws-nitro-enclaves-sdk-c");
}
