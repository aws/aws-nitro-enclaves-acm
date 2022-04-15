// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::mngtok::Error;
use nix::unistd;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;

pub struct HttpdService {}

impl HttpdService {
    pub fn write_tls_entries(
        path: &str,
        uid: Option<nix::unistd::Uid>,
        gid: Option<nix::unistd::Gid>,
        key_uri: &str,
        cert_path: Option<String>,
    ) -> Result<(), Error> {
        let mut to_write = String::new();
        OpenOptions::new()
            .read(true)
            .open(path)
            .map_err(Error::TargetIoError)
            .and_then(|file| {
                let reader = BufReader::new(&file);
                for line in reader.lines() {
                    if let Ok(l) = line {
                        let nl = {
                            if l.starts_with("SSLCertificateKeyFile") {
                                format!("SSLCertificateKeyFile \"{}\"", key_uri)
                            } else if l.starts_with("SSLCertificateFile") {
                                match cert_path {
                                    Some(ref cp) => format!("SSLCertificateFile \"{}\"", cp),
                                    None => l,
                                }
                            } else {
                                l
                            }
                        };
                        to_write.push_str(&nl);
                        to_write.push_str("\n");
                    }
                }
                Ok(())
            })?;

        OpenOptions::new()
            .write(true)
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
                write!(file, "{}", to_write).map_err(Error::TargetIoError)?;
                Ok(())
            })?;
        Ok(())
    }
}
