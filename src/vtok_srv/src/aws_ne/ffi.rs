// Copyright 2020-2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(dead_code)]

pub use std::os::raw::{c_int, c_ulong, c_void};
pub type c_size_t = usize;

/// Must be kept in sync with the endpoint proxy
pub const AWS_NE_VSOCK_PROXY_ADDR: [u8; 2] = [0x33u8, 0x00];
pub const AWS_NE_VSOCK_PROXY_PORT: u16 = 8000;
pub const AWS_SOCKET_VSOCK_DOMAIN: c_int = 3;
pub const AWS_ADDRESS_MAX_LEN: usize = 108;
pub const KMS_MAX_DECRYPT_LEN: usize = 4096;

#[repr(C)]
pub struct aws_byte_buf {
    pub len: c_size_t,
    pub buffer: *mut u8,
    capacity: c_size_t,
    allocator: *mut aws_allocator,
}
#[repr(C)]
pub struct aws_string {
    _ph: [u8; 0],
}
#[repr(C)]
pub struct aws_allocator {
    _ph: [u8; 0],
}
#[repr(C)]
pub struct aws_nitro_enclaves_kms_client_configuration {
    _ph: [u8; 0],
}
#[repr(C)]
pub struct aws_nitro_enclaves_kms_client {
    _ph: [u8; 0],
}

#[repr(C)]
pub struct aws_socket_endpoint {
    pub address: [u8; AWS_ADDRESS_MAX_LEN],
    pub port: u16,
}

/// Imported SDK APIs
extern "C" {
    /// Aws-C-Common
    pub fn aws_byte_buf_from_array(bytes: *mut c_void, len: c_size_t) -> aws_byte_buf;
    pub fn aws_string_new_from_array(
        allocator: *mut aws_allocator,
        bytes: *const u8,
        len: c_size_t,
    ) -> *mut aws_string;
    pub fn aws_string_destroy_secure(string: *mut aws_string);
    pub fn aws_byte_buf_clean_up_secure(buf: *mut aws_byte_buf);

    /// AWS Nitro Enclaves SDK
    pub fn aws_nitro_enclaves_library_init(allocator: *mut aws_allocator);
    pub fn aws_nitro_enclaves_library_clean_up();
    pub fn aws_nitro_enclaves_get_allocator() -> *mut aws_allocator;

    pub fn aws_nitro_enclaves_kms_client_config_default(
        region: *mut aws_string,
        endpoint: *mut aws_socket_endpoint,
        domain: c_int,
        access_key_id: *mut aws_string,
        secret_access_key: *mut aws_string,
        session_token: *mut aws_string,
    ) -> *mut aws_nitro_enclaves_kms_client_configuration;

    pub fn aws_nitro_enclaves_kms_client_config_destroy(
        config: *mut aws_nitro_enclaves_kms_client_configuration,
    );

    pub fn aws_nitro_enclaves_kms_client_new(
        config: *mut aws_nitro_enclaves_kms_client_configuration,
    ) -> *mut aws_nitro_enclaves_kms_client;

    pub fn aws_nitro_enclaves_kms_client_destroy(client: *mut aws_nitro_enclaves_kms_client);

    pub fn aws_kms_decrypt_blocking(
        client: *mut aws_nitro_enclaves_kms_client,
        key_id: *mut aws_string,
        encryption_algorithm: *mut aws_string,
        ciphertext: *const aws_byte_buf,
        plaintext: *mut aws_byte_buf,
    ) -> c_int;
}
