// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::mngtok::Error;
use nix::unistd;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;

pub struct NginxService {}

impl NginxService {
    pub fn write_tls_entries(
        path: &str,
        uid: Option<nix::unistd::Uid>,
        gid: Option<nix::unistd::Gid>,
        key_uri: &str,
        cert_path: Option<String>,
    ) -> Result<(), Error> {
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o440)
            .open(path)
            .map_err(Error::TargetIoError)
            .and_then(|mut file| {
                unistd::fchown(file.as_raw_fd(), uid, gid).map_err(Error::NixError)?;
                nix::sys::stat::fchmod(
                    file.as_raw_fd(),
                    // Safe becase 0o440 is valid.
                    unsafe { nix::sys::stat::Mode::from_bits_unchecked(0o440) },
                )
                .map_err(Error::NixError)?;
                write!(file, "ssl_certificate_key \"engine:pkcs11:{}\";\n", key_uri)
                    .map_err(Error::TargetIoError)?;
                if let Some(cp) = cert_path {
                    write!(file, "ssl_certificate \"{}\";\n", cp).map_err(Error::TargetIoError)?;
                }
                Ok(())
            })?;
        Ok(())
    }
}
