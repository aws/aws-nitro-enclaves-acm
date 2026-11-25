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
    /// Replaces the SSLCertificateKeyFile / SSLCertificateFile directives in one config line.
    /// Leading whitespace is allowed (and kept), so indented httpd configs are rewritten too.
    fn rewrite_tls_line(l: String, key_uri: &str, cert_path: &Option<String>) -> String {
        let indent_len = l.len() - l.trim_start().len();
        let (indent, directive) = l.split_at(indent_len);
        if directive.starts_with("SSLCertificateKeyFile") {
            format!("{}SSLCertificateKeyFile \"{}\"", indent, key_uri)
        } else if directive.starts_with("SSLCertificateFile") {
            match cert_path {
                Some(cp) => format!("{}SSLCertificateFile \"{}\"", indent, cp),
                None => l,
            }
        } else {
            l
        }
    }

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
                        let nl = Self::rewrite_tls_line(l, key_uri, &cert_path);
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

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "pkcs11:token=acm;object=key";

    #[test]
    fn rewrites_directives_at_line_start() {
        let cp = Some("/etc/pki/tls/certs/acm.pem".to_string());
        assert_eq!(
            HttpdService::rewrite_tls_line("SSLCertificateKeyFile /old.key".to_string(), KEY, &cp),
            format!("SSLCertificateKeyFile \"{}\"", KEY)
        );
        assert_eq!(
            HttpdService::rewrite_tls_line("SSLCertificateFile /old.pem".to_string(), KEY, &cp),
            "SSLCertificateFile \"/etc/pki/tls/certs/acm.pem\""
        );
    }

    #[test]
    fn rewrites_indented_directives_and_keeps_indentation() {
        let cp = Some("/etc/pki/tls/certs/acm.pem".to_string());
        assert_eq!(
            HttpdService::rewrite_tls_line("    SSLCertificateKeyFile /old.key".to_string(), KEY, &cp),
            format!("    SSLCertificateKeyFile \"{}\"", KEY)
        );
        assert_eq!(
            HttpdService::rewrite_tls_line("\tSSLCertificateFile /old.pem".to_string(), KEY, &cp),
            "\tSSLCertificateFile \"/etc/pki/tls/certs/acm.pem\""
        );
    }

    #[test]
    fn leaves_other_lines_and_missing_cert_path_alone() {
        let line = "  SSLCertificateFile /old.pem".to_string();
        assert_eq!(HttpdService::rewrite_tls_line(line.clone(), KEY, &None), line);
        for other in ["# SSLCertificateKeyFile /old.key", "  ServerName example.com", ""] {
            assert_eq!(HttpdService::rewrite_tls_line(other.to_string(), KEY, &None), other);
        }
    }
}
