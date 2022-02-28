// Copyright 2020-2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

extern crate libc;

pub mod config;
pub mod util;

pub mod defs {
    /// Manufacturer of the various PKCS#11 objects (library, tokens, slots).
    pub const MANUFACTURER: &str = "Amazon";

    /// The filesystem path used to store the p11ne DB/config file. This is read by the PKCS#11
    /// provider (vtok_p11), and written to by the RPC server (vtok_srv).
    pub const DEVICE_CONFIG_PATH: &str = "./config.json";
    /// PKCS#11 provider description, as reported by vtok_p11.
    pub const DEVICE_DESCRIPTION: &str = "p11ne";
    /// Maximum number of slots/tokens exposed by our PKCS#11 provider.
    pub const DEVICE_MAX_SLOTS: usize = 128;

    /// PKCS#11 provider slot description.
    pub const SLOT_DESCRIPTION: &str = "p11ne-slot";

    /// Token expiration time, in seconds. A refresh operation (i.e. reattestation) MUST be
    /// performed before this timer expires. Otherwise, the token will be automatically removed
    /// from its slot.
    pub const TOKEN_EXPIRY_SECS: u64 = 48 * 3600;
    /// PKCS#11 token model, as reported by vtok_p11.
    pub const TOKEN_MODEL: &str = "p11ne-token";
    /// Minimum length (in bytes) of a token PIN.
    pub const TOKEN_MIN_PIN_LEN: usize = 4;
    /// Maximum length (in bytes) of a token PIN.
    pub const TOKEN_MAX_PIN_LEN: usize = 64;
    /// Minimum length (in bytes) of a token label.
    pub const TOKEN_MIN_LABEL_LEN: usize = 1;
    /// Maximum length (in bytes) of a token label.
    pub const TOKEN_MAX_LABEL_LEN: usize = 32;
    /// Maximum number of concurrent (read-only) sessions supported by a single token exposed by
    /// vtok_p11.
    pub const TOKEN_MAX_SESSIONS: usize = 1024;

    /// I/O timeout (in milliseconds) set for the RPC client-server communication.
    pub const RPC_STREAM_TIMEOUT_MS: u64 = 1000;
}
