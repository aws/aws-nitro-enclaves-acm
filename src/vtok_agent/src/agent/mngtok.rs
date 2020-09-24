// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::process::Command;
use std::rc::Rc;
use std::time::{Duration, Instant};

use log::{debug, error, info};
use nix::unistd;
use serde::{Deserialize, Serialize};
use serde_json;

use crate::imds;
use crate::util;
use crate::{config, defs, enclave, enclave::P11neEnclave};
use vtok_rpc::api::schema;

#[derive(Debug)]
pub enum Error {
    AcmDbFetchError(Option<i32>, String),
    AcmDbParseError(serde_json::Error),
    AddTokenError(schema::ApiError),
    AwsCliExecError(std::io::Error),
    BadGroup(String),
    BadUser(String),
    EnclaveError(enclave::Error),
    FileDbError(std::io::Error),
    FileDbParseError(serde_json::Error),
    NginxNotActive,
    NginxReloadError(Option<i32>),
    NixError(nix::Error),
    ImdsError(imds::Error),
    PinGenerationError(std::io::Error),
    RefreshTokenError(schema::ApiError),
    SourceDbEmpty,
    SwapOnError(schema::ApiError),
    SwapOffError(schema::ApiError),
    SystemdExecError(std::io::Error),
    UpdateTokenError(schema::ApiError),
    TargetIoError(std::io::Error),
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
struct AcmDb {
    certificate: String,
    #[serde(rename = "certificateChain")]
    certificate_chain: String,
    #[serde(rename = "encryptedPrivateKey")]
    encrypted_private_key: String,
    #[serde(rename = "encryptionMethod")]
    encryption_method: String,
}

type FileDb = Vec<schema::PrivateKey>;

enum DbSource {
    Acm {
        cert_arn: String,
        db: AcmDb,
        bucket: String,
    },
    File {
        db: FileDb,
    },
}

impl DbSource {
    pub fn new(source_config: config::Source) -> Result<Self, Error> {
        match source_config {
            config::Source::Acm {
                certificate_arn,
                bucket,
            } => {
                let bucket = bucket.unwrap_or(defs::DEFAULT_ACM_BUCKET.to_string());
                Ok(Self::Acm {
                    db: Self::fetch_acm_db(certificate_arn.as_str(), bucket.as_str())?,
                    cert_arn: certificate_arn,
                    bucket,
                })
            }
            config::Source::FileDb { path } => Ok(Self::File {
                db: Self::fetch_file_db(path.as_str())?,
            }),
        }
    }

    pub fn update(&mut self) -> Result<bool, Error> {
        match self {
            Self::Acm {
                ref mut db,
                cert_arn,
                bucket,
            } => {
                let new_db = Self::fetch_acm_db(cert_arn, bucket)?;
                let res = new_db != *db;
                *db = new_db;
                Ok(res)
            }
            Self::File { .. } => Ok(false),
        }
    }

    pub fn to_schema_keys(&self) -> Vec<schema::PrivateKey> {
        match self {
            Self::Acm { db, .. } => vec![schema::PrivateKey {
                id: 1,
                label: "acm-key".to_string(),
                encrypted_pem_b64: db.encrypted_private_key.clone(),
            }],
            Self::File { db, .. } => db.as_slice().to_vec(),
        }
    }

    pub fn cert_pem(&self) -> Option<&str> {
        match self {
            Self::Acm { db, .. } => Some(db.certificate.as_str()),
            Self::File { .. } => None,
        }
    }

    pub fn cert_chain_pem(&self) -> Option<&str> {
        match self {
            Self::Acm { db, .. } => Some(db.certificate_chain.as_str()),
            Self::File { .. } => None,
        }
    }

    fn fetch_acm_db(cert_arn: &str, bucket: &str) -> Result<AcmDb, Error> {
        debug!("Fetching cert for arn: {}", cert_arn);
        let s3_url = format!(
            "s3://{}-ec2-enclave-certificate-{}-{}/{}/{}",
            imds::partition().map_err(Error::ImdsError)?,
            imds::region().map_err(Error::ImdsError)?,
            bucket,
            imds::role_arn().map_err(Error::ImdsError)?,
            cert_arn
        );
        let output = Command::new("aws")
            .arg("s3")
            .args(&[
                "--region",
                imds::region().map_err(Error::ImdsError)?.as_str(),
            ])
            .args(&["cp", s3_url.as_str(), "-"])
            .output()
            .map_err(Error::AwsCliExecError)?;
        if !output.status.success() {
            return Err(Error::AcmDbFetchError(
                output.status.code(),
                String::from_utf8_lossy(output.stderr.as_slice()).to_string(),
            ));
        }
        serde_json::from_slice::<AcmDb>(output.stdout.as_slice()).map_err(Error::AcmDbParseError)
    }

    fn fetch_file_db(path: &str) -> Result<FileDb, Error> {
        OpenOptions::new()
            .read(true)
            .open(path)
            .and_then(|mut f| {
                let mut buf = Vec::new();
                f.read_to_end(&mut buf)?;
                Ok(buf)
            })
            .map_err(Error::FileDbError)
            .and_then(|buf| {
                serde_json::from_slice::<FileDb>(buf.as_slice()).map_err(Error::FileDbParseError)
            })
    }
}

pub struct ManagedToken {
    pub label: String,
    pub pin: String,
    db: DbSource,
    target: Option<config::Target>,
    enclave: Rc<P11neEnclave>,
    is_swapped: bool,
    swap_pin: String,
    refresh_interval: Duration,
    next_refresh: Instant,
}

impl ManagedToken {
    pub fn new(
        token_config: config::Token,
        enclave: Rc<P11neEnclave>,
        swap_pin: String,
    ) -> Result<Self, Error> {
        let pin = match token_config.pin {
            Some(pin) => pin,
            None => util::generate_pkcs11_pin().map_err(Error::PinGenerationError)?,
        };
        Ok(Self {
            label: token_config.label,
            pin,
            db: DbSource::new(token_config.source)?,
            target: token_config.target,
            enclave,
            is_swapped: false,
            swap_pin,
            refresh_interval: Duration::from_secs(
                token_config
                    .refresh_interval_secs
                    .unwrap_or(defs::DEFAULT_TOKEN_REFRESH_INTERVAL_SECS),
            ),
            next_refresh: Instant::now(),
        })
    }

    pub fn sync(&mut self) -> Result<(), Error> {
        let db_changed = self.db.update()?;
        let is_online = self
            .enclave
            .rpc(schema::ApiRequest::DescribeToken {
                label: self.label.clone(),
                pin: self.pin.clone(),
            })
            .map_err(Error::EnclaveError)?
            .is_ok();

        match (is_online, db_changed, self.target.as_ref()) {
            (true, true, Some(config::Target::NginxStanza { .. })) => {
                info!(
                    "NGINX certificate changed. Updating token {}",
                    self.label.as_str()
                );

                debug!("Switching token={} to swap", self.label.as_str());
                self.swap_on()?;

                debug!("Moving NGINX to swap token");
                self.satisfy_target_or_pass();

                debug!("Updating token {}", self.label.as_str());
                self.enclave
                    .rpc(schema::ApiRequest::UpdateToken {
                        label: self.label.clone(),
                        pin: self.pin.clone(),
                        token: self.to_schema_token()?,
                    })
                    .map_err(Error::EnclaveError)?
                    .map_err(Error::UpdateTokenError)?;

                self.swap_off();

                debug!("Moving NGINX back from swap");
                self.satisfy_target_or_pass();

                debug!("Clearing swap");
                self.clear_swap()?;
            }
            (true, true, None) => {
                info!(
                    "DB change detected for token {}. Updating",
                    self.label.as_str()
                );
                self.enclave
                    .rpc(schema::ApiRequest::UpdateToken {
                        label: self.label.clone(),
                        pin: self.pin.clone(),
                        token: self.to_schema_token()?,
                    })
                    .map_err(Error::EnclaveError)?
                    .map_err(Error::UpdateTokenError)?;
            }
            (true, false, _) => {
                if self.next_refresh <= Instant::now() {
                    info!("Refreshing token {}", self.label.as_str());
                    self.enclave
                        .rpc(schema::ApiRequest::RefreshToken {
                            label: self.label.clone(),
                            pin: self.pin.clone(),
                            envelope_key: Self::kms_envelope_key()?,
                        })
                        .map_err(Error::EnclaveError)?
                        .map_err(Error::RefreshTokenError)?;
                    self.next_refresh += self.refresh_interval;
                }
            }
            (false, _, _) => {
                self.enclave
                    .rpc(schema::ApiRequest::AddToken {
                        token: self.to_schema_token()?,
                    })
                    .map_err(Error::EnclaveError)?
                    .map_err(Error::AddTokenError)?;
                self.satisfy_target_or_pass();
            }
        }

        Ok(())
    }

    fn satisfy_target_or_pass(&self) {
        self.satisfy_target().unwrap_or_else(|err| {
            error!(
                "Unable to satisfy target for token {}: {:?}",
                self.label.as_str(),
                err
            )
        });
    }

    fn satisfy_target(&self) -> Result<(), Error> {
        let token_label = if self.is_swapped {
            defs::SWAP_TOKEN_LABEL
        } else {
            self.label.as_str()
        };
        let (key_id, key_label) = self
            .db
            .to_schema_keys()
            .iter()
            .map(|k| (k.id, k.label.clone()))
            .next()
            .ok_or(Error::SourceDbEmpty)?;
        let key_uri = format!(
            "pkcs11:model={};manufacturer={};token={};id=%{:02x};object={};type=private?pin-value={}",
            "p11ne-token",
            "Amazon",
            token_label,
            key_id,
            key_label.as_str(),
            self.pin.as_str(),
        );

        match self.target {
            None => (),
            Some(config::Target::NginxStanza {
                ref user,
                ref group,
                ref path,
                force_start,
            }) => {
                let uid = match user.as_ref() {
                    Some(name) => Some(
                        unistd::User::from_name(name)
                            .map_err(Error::NixError)?
                            .ok_or(Error::BadUser(name.to_string()))?
                            .uid,
                    ),
                    None => None,
                };
                let gid = match group.as_ref() {
                    Some(name) => Some(
                        unistd::Group::from_name(name)
                            .map_err(Error::NixError)?
                            .ok_or(Error::BadGroup(name.to_string()))?
                            .gid,
                    ),
                    None => None,
                };

                let cert_path = match self.db.cert_pem() {
                    None => None,
                    Some(cert_pem) => {
                        let cert_path = format!(
                            "{}/nginx-cert-{}.pem",
                            defs::RUN_DIR,
                            util::bytes_to_hex(token_label.as_bytes())
                        );
                        debug!("Writing {}", &cert_path);
                        OpenOptions::new()
                            .create(true)
                            .truncate(true)
                            .write(true)
                            .open(cert_path.as_str())
                            .and_then(|mut file| {
                                file.write_all(cert_pem.as_bytes())?;
                                if let Some(chain_pem) = self.db.cert_chain_pem() {
                                    file.write_all(chain_pem.as_bytes())?;
                                }
                                Ok(())
                            })
                            .map_err(Error::TargetIoError)?;
                        debug!("Done writing {}", &cert_path);
                        Some(cert_path)
                    }
                };

                debug!("Ensuring dirs for file: {}", path);
                util::create_dirs_for_file(path).map_err(Error::TargetIoError)?;

                debug!("Writing {}", &path);
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
                            write!(file, "ssl_certificate \"{}\";\n", cp)
                                .map_err(Error::TargetIoError)?;
                        }
                        Ok(())
                    })?;
                debug!("Done writing {}", &path);

                Self::reload_nginx(force_start.unwrap_or(defs::DEFAULT_NGINX_FORCE_START))?;
            }
        }
        Ok(())
    }

    fn to_schema_token(&self) -> Result<schema::Token, Error> {
        Ok(schema::Token {
            label: self.label.clone(),
            pin: self.pin.clone(),
            envelope_key: Self::kms_envelope_key()?,
            keys: self.db.to_schema_keys(),
        })
    }

    fn swap_on(&mut self) -> Result<(), Error> {
        self.enclave
            .rpc(schema::ApiRequest::AddToken {
                token: self.to_schema_token().map(|mut tok| {
                    tok.label = defs::SWAP_TOKEN_LABEL.to_string();
                    tok.pin = self.swap_pin.clone();
                    tok
                })?,
            })
            .map_err(Error::EnclaveError)?
            .map_err(Error::SwapOnError)?;

        self.is_swapped = true;

        Ok(())
    }

    fn swap_off(&mut self) {
        self.is_swapped = false;
    }

    fn clear_swap(&self) -> Result<(), Error> {
        self.enclave
            .rpc(schema::ApiRequest::RemoveToken {
                label: defs::SWAP_TOKEN_LABEL.to_string(),
                pin: self.swap_pin.clone(),
            })
            .map_err(Error::EnclaveError)?
            .map_err(Error::SwapOffError)?;
        Ok(())
    }

    fn kms_envelope_key() -> Result<schema::EnvelopeKey, Error> {
        let creds = imds::creds().map_err(Error::ImdsError)?;
        Ok(schema::EnvelopeKey::Kms {
            region: imds::region().map_err(Error::ImdsError)?,
            access_key_id: creds.access_key_id,
            secret_access_key: creds.secret_access_key,
            session_token: creds.token,
        })
    }

    fn reload_nginx(force_start: bool) -> Result<(), Error> {
        Command::new("systemctl")
            .args(&["is-active", "-q", "nginx.service"])
            .status()
            .map_err(Error::SystemdExecError)
            .and_then(|status| {
                let cmd = if status.success() {
                    info!("Reloading NGINX config");
                    "reload"
                } else {
                    if force_start {
                        info!("NGINX is not running. Starting it now.");
                        "start"
                    } else {
                        error!("Unable to reload NGINX config: nginx.service is inactive and force starting is disabled");
                        return Err(Error::NginxNotActive);
                    }
                };
                Command::new("systemctl")
                    .args(&[cmd, "nginx.service"])
                    .status()
                    .map_err(Error::SystemdExecError)
                    .and_then(|status| {
                        if status.success() {
                            Ok(())
                        } else {
                            Err(Error::NginxReloadError(status.code()))
                        }
                    })
            })
    }
}