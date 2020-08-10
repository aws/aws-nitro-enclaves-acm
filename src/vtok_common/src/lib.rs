// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

extern crate libc;

pub mod config;
pub mod util;

pub mod defs {
    pub const DEVICE_CONFIG_PATH: &str = "/vtok/device/config.json";
    pub const DEVICE_MAX_SLOTS: usize = 4;

    pub const TOKEN_MIN_PIN_LEN: usize = 4;
    pub const TOKEN_MAX_PIN_LEN: usize = 64;
    pub const TOKEN_MIN_LABEL_LEN: usize = 1;
    pub const TOKEN_MAX_LABEL_LEN: usize = 32;
    pub const TOKEN_EXPIRY_SECS: u64 = 48 * 3600;

    pub const RPC_STREAM_TIMEOUT_MS: u64 = 1000;
}
