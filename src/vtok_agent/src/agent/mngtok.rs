// Copyright 2020-2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::process::Command;
use std::rc::Rc;
use std::time::{Duration, Instant};

use log::{debug, error, info};
use nix::unistd;
use serde::{Deserialize, Serialize};
use serde_json;

use super::{httpd, nginx, PostSyncAction};
use crate::imds;
use crate::util;
use crate::{config, defs, enclave, enclave::P11neEnclave};
use vtok_rpc::api::schema;

#[derive(Debug)]
pub enum Error {
    KeyMaterialDbFetchError(Option<i32>, String),
    KeyMaterialDbParseError(serde_json::Error),
    AddTokenError(schema::ApiError),
    AwsCliExecError(std::io::Error),
    BadGroup(String),
    BadUser(String),
    EnclaveError(enclave::Error),
    FileDbError(std::io::Error),
    FileDbParseError(serde_json::Error),
    NixError(nix::Error),
    ImdsError(imds::Error),
    PinGenerationError(std::io::Error),
    RefreshTokenError(schema::ApiError),
    SourceDbEmpty,
    UpdateTokenError(schema::ApiError),
    TargetIoError(std::io::Error),
    ManagedServiceUnknown,
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
struct KeyMaterialDb {
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
        db: KeyMaterialDb,
        bucket: String,
    },
    S3 {
        uri: String,
        db: KeyMaterialDb,
    },
    File {
        db: FileDb,
    },
}

struct KeyMaterialSchemaBuilder<'a> {
    label: &'a str,
    encrypted_pem_b64: &'a String,
    cert_pem: Option<&'a str>,
    cert_chain_pem: Option<&'a str>,
}

impl<'a> KeyMaterialSchemaBuilder<'a> {
    fn new(label: &'a str, encrypted_pem_b64: &'a String) -> Self {
        KeyMaterialSchemaBuilder {
            label,
            encrypted_pem_b64,
            cert_pem: None,
            cert_chain_pem: None,
        }
    }

    fn cert_pem(mut self, cert_pem: Option<&'a str>) -> Self {
        self.cert_pem = cert_pem;
        self
    }

    fn cert_chain_pem(mut self, cert_chain_pem: Option<&'a str>) -> Self {
        self.cert_chain_pem = cert_chain_pem;
        self
    }

    fn build(&self) -> Vec<schema::PrivateKey> {
        let optcerts = self.cert_pem.map(|c| {
            let mut cc = c.to_string();
            self.cert_chain_pem.map(|ch| cc.push_str(ch));
            cc
        });

        vec![schema::PrivateKey {
            id: 1,
            label: self.label.to_string(),
            encrypted_pem_b64: self.encrypted_pem_b64.to_string(),
            cert_pem: optcerts,
        }]
    }
}

impl DbSource {
    pub fn new(source_config: config::Source) -> Result<Self, Error> {
        match source_config {
            config::Source::Acm {
                certificate_arn,
                bucket,
            } => {
                let bucket = bucket.unwrap_or(defs::DEFAULT_ACM_BUCKET.to_string());
                let uri = DbSource::new_acm_db_s3_uri(&certificate_arn, &bucket)?;

                Ok(Self::Acm {
                    db: Self::fetch_from_s3(&uri)?,
                    cert_arn: certificate_arn,
                    bucket,
                })
            },
            config::Source::S3 {
                uri,
            } => {
                Ok(Self::S3 {
                    db: Self::fetch_from_s3(&uri)?,
                    uri: uri,
                })
            },
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
                let uri = DbSource::new_acm_db_s3_uri(cert_arn, bucket)?;
                let new_db = Self::fetch_from_s3(&uri)?;
                let res = new_db != *db;
                *db = new_db;
                Ok(res)
            },
            Self::S3 {
                ref mut db,
                uri
            } => {
                let new_db = Self::fetch_from_s3(&uri)?;
                let res = new_db != *db;
                *db = new_db;
                Ok(res)
            },
            Self::File { .. } => Ok(false),
        }
    }

    pub fn to_schema_keys(&self) -> Vec<schema::PrivateKey> {
        match self {
            Self::File { db, .. } => db.as_slice().to_vec(),
            other_sources => {
                let (token_label, db) = match other_sources {
                    Self::Acm { db, .. } => {
                        ("acm-key", db)
                    },
                    Self::S3 { db, .. } => {
                        ("s3-key", db)
                    },
                    _ => {
                        panic!("Unsupported source for key materials!");
                    }
                };

                KeyMaterialSchemaBuilder::new(token_label, &db.encrypted_private_key)
                    .cert_pem(self.cert_pem())
                    .cert_chain_pem(self.cert_chain_pem())
                    .build()
            }
        }
    }

    pub fn cert_pem(&self) -> Option<&str> {
        match self {
            Self::Acm { db, .. } | Self::S3 { db, .. } => Some(db.certificate.as_str()),
            Self::File { .. } => None,
        }
    }

    pub fn cert_chain_pem(&self) -> Option<&str> {
        match self {
            Self::Acm { db, .. } | Self::S3 { db, .. } => Some(db.certificate_chain.as_str()),
            Self::File { .. } => None,
        }
    }

    fn new_acm_db_s3_uri(cert_arn: &str, bucket: &str) -> Result<String, Error> {
        Ok(format!(
            "s3://{}-ec2-enclave-certificate-{}-{}/{}/{}",
            imds::partition().map_err(Error::ImdsError)?,
            imds::region().map_err(Error::ImdsError)?,
            bucket,
            imds::role_arn().map_err(Error::ImdsError)?,
            cert_arn,
        ))
    }

    fn fetch_from_s3(s3_uri: &str) -> Result<KeyMaterialDb, Error> {
        debug!("Fetching from {}", s3_uri);
        let output = Command::new("aws")
            .arg("s3")
            .args(&[
                "--region",
                imds::region().map_err(Error::ImdsError)?.as_str(),
            ])
            .args(&["cp", s3_uri, "-"])
            .output()
            .map_err(Error::AwsCliExecError)?;
        if !output.status.success() {
            return Err(Error::KeyMaterialDbFetchError(
                output.status.code(),
                String::from_utf8_lossy(output.stderr.as_slice()).to_string(),
            ));
        }
        serde_json::from_slice::<KeyMaterialDb>(output.stdout.as_slice()).map_err(Error::KeyMaterialDbParseError)
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

#[derive(Debug, Clone, Copy)]
pub enum ManagedService {
    Nginx,
    Httpd,
}

impl ManagedService {
    pub fn from_str(service: &str) -> Result<Self, Error> {
        match service {
            defs::SERVICE_NGINX => Ok(ManagedService::Nginx),
            defs::SERVICE_HTTPD => Ok(ManagedService::Httpd),
            _ => Err(Error::ManagedServiceUnknown),
        }
    }
}

pub struct ManagedToken {
    pub label: String,
    pub pin: String,
    db: DbSource,
    target: Option<config::Target>,
    enclave: Rc<P11neEnclave>,
    refresh_interval: Duration,
    next_refresh: Instant,
    service: ManagedService,
}

impl ManagedToken {
    pub fn new(
        token_config: config::Token,
        enclave: Rc<P11neEnclave>,
        service: ManagedService,
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
            refresh_interval: Duration::from_secs(
                token_config
                    .refresh_interval_secs
                    .unwrap_or(defs::DEFAULT_TOKEN_REFRESH_INTERVAL_SECS),
            ),
            next_refresh: Instant::now(),
            service,
        })
    }

    fn update(&mut self) -> Result<Option<PostSyncAction>, Error> {
        self.enclave
            .update_token(
                self.label.clone(),
                self.pin.clone(),
                self.to_schema_token()?,
            )
            .map_err(Error::EnclaveError)?
            .map_err(Error::UpdateTokenError)?;

        if let Some(_target) = self.target.as_ref() {
            debug!("Updating managed service configuration.");
            return self.satisfy_target(true).or_else(|e| {
                error!(
                    "Failed to update managed service configuration for token {}: {:?}",
                    self.label.as_str(),
                    e
                );
                Ok(None)
            });
        }

        Ok(None)
    }

    fn refresh(&mut self) -> Result<(), Error> {
        self.enclave
            .refresh_token(
                self.label.clone(),
                self.pin.clone(),
                Self::kms_envelope_key()?,
            )
            .map_err(Error::EnclaveError)?
            .map_err(Error::RefreshTokenError)?;
        self.next_refresh += self.refresh_interval;

        Ok(())
    }

    fn add(&mut self) -> Result<Option<PostSyncAction>, Error> {
        self.enclave
            .add_token(self.to_schema_token()?)
            .map_err(Error::EnclaveError)?
            .map_err(Error::AddTokenError)?;
        return self.satisfy_target(true).or_else(|e| {
            error!(
                "Unable to satisfy target for token {}: {:?}",
                self.label.as_str(),
                e
            );
            Ok(None)
        });

        Ok(None)
    }

    pub fn sync(&mut self) -> Result<Option<PostSyncAction>, Error> {
        let db_changed = self.db.update()?;
        let is_online = self
            .enclave
            .describe_token(self.label.clone(), self.pin.clone())
            .map_err(Error::EnclaveError)?
            .is_ok();

        match (is_online, db_changed) {
            (true, true) => {
                info!("DB change detected. Updating token: {}.", self.label.as_str());
                return self.update();
            }
            (true, false) => {
                if self.next_refresh <= Instant::now() {
                    info!("Refreshing token: {}.", self.label.as_str());
                    self.refresh()?;
                }
            }
            (false, _) => {
                debug!("Adding token: {}.", self.label.as_str());
                return self.add();
            }
        }

        Ok(None)
    }

    fn satisfy_target(&self, restart_hint: bool) -> Result<Option<PostSyncAction>, Error> {
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
            self.label.as_str(),
            key_id,
            key_label.as_str(),
            self.pin.as_str(),
        );

        match self.target {
            None => Ok(None),
            Some(config::Target::Conf {
                ref user,
                ref group,
                ref path,
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
                        let cert_name = match self.service {
                            ManagedService::Nginx => "nginx-cert",
                            ManagedService::Httpd => "httpd-cert",
                        };
                        let cert_path = format!(
                            "{}/{}-{}.pem",
                            defs::RUN_DIR,
                            cert_name,
                            util::bytes_to_hex(self.label.as_bytes())
                        );
                        OpenOptions::new()
                            .create(true)
                            .truncate(true)
                            .write(true)
                            .open(cert_path.as_str())
                            .and_then(|mut file| {
                                file.write_all(cert_pem.as_bytes())?;
                                if let Some(chain_pem) = self.db.cert_chain_pem() {
                                    file.write(b"\n")?;
                                    file.write_all(chain_pem.as_bytes())?;
                                }
                                Ok(())
                            })
                            .map_err(Error::TargetIoError)?;
                        Some(cert_path)
                    }
                };

                util::create_dirs_for_file(path).map_err(Error::TargetIoError)?;

                let post_action = match self.service {
                    ManagedService::Nginx => {
                        nginx::NginxService::write_tls_entries(
                            &path, uid, gid, &key_uri, cert_path,
                        )?;

                        restart_hint.then(|| PostSyncAction::RestartNginx)
                    }
                    ManagedService::Httpd => {
                        httpd::HttpdService::write_tls_entries(
                            &path, uid, gid, &key_uri, cert_path,
                        )?;

                        restart_hint.then(|| PostSyncAction::RestartHttpd)
                    }
                };
                Ok(post_action)
            }
        }
    }

    fn to_schema_token(&self) -> Result<schema::Token, Error> {
        Ok(schema::Token {
            label: self.label.clone(),
            pin: self.pin.clone(),
            envelope_key: Self::kms_envelope_key()?,
            keys: self.db.to_schema_keys(),
        })
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
}
