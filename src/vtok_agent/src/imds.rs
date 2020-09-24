// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::{Arc, Mutex};

use lazy_static::lazy_static;
use serde::Deserialize;
use serde_json;
use std::process::Command;

lazy_static! {
    static ref IMDS_CACHE: Arc<Mutex<Option<ImdsCache>>> = Arc::new(Mutex::new(None));
}

#[derive(Debug)]
pub enum Error {
    IoError(std::io::Error),
    ProcessError(Option<i32>, String),
    Utf8Error(std::string::FromUtf8Error),
    ParseError(serde_json::Error),
    PoisonedLock,
}

#[allow(non_snake_case, dead_code)]
#[derive(Debug, Deserialize)]
pub struct IamInfo {
    #[serde(rename = "Code")]
    pub code: String,
    #[serde(rename = "LastUpdated")]
    pub last_updated: String,
    #[serde(rename = "InstanceProfileArn")]
    pub instance_profile_arn: String,
    #[serde(rename = "InstanceProfileId")]
    pub instance_profile_id: String,
}

#[allow(non_snake_case, dead_code)]
#[derive(Clone, Debug, Deserialize)]
pub struct SecurityCredentials {
    #[serde(rename = "Code")]
    pub code: String,
    #[serde(rename = "LastUpdated")]
    pub last_updated: String,
    #[serde(rename = "Type")]
    pub type_: String,
    #[serde(rename = "AccessKeyId")]
    pub access_key_id: String,
    #[serde(rename = "SecretAccessKey")]
    pub secret_access_key: String,
    #[serde(rename = "Token")]
    pub token: String,
    #[serde(rename = "Expiration")]
    pub expiration: String,
}

pub fn partition() -> Result<String, Error> {
    get_with(|cache| cache.partition.clone())
}

pub fn region() -> Result<String, Error> {
    get_with(|cache| cache.region.clone())
}

pub fn role_arn() -> Result<String, Error> {
    get_with(|cache| cache.role_arn.clone())
}

pub fn creds() -> Result<SecurityCredentials, Error> {
    get_with(|cache| cache.creds.clone())
}

pub fn invalidate_cache() -> Result<(), Error> {
    IMDS_CACHE
        .lock()
        .map(|mut opt| {
            opt.take();
        })
        .map_err(|_| Error::PoisonedLock)
}

struct ImdsCache {
    partition: String,
    region: String,
    role_arn: String,
    creds: SecurityCredentials,
}

impl ImdsCache {
    fn new() -> Result<Self, Error> {
        Ok(Self {
            partition: Self::fetch_partition()?,
            region: Self::fetch_region()?,
            role_arn: Self::fetch_role_arn()?,
            creds: Self::fetch_creds()?,
        })
    }

    fn fetch(key: &str) -> Result<String, Error> {
        let url = format!("http://169.254.169.254{}", key);
        let output = Command::new("curl")
            .arg("-fs")
            .arg(url)
            .output()
            .map_err(Error::IoError)?;
        if !output.status.success() {
            return Err(Error::ProcessError(
                output.status.code(),
                String::from_utf8_lossy(&output.stderr).to_string(),
            ));
        }
        String::from_utf8(output.stdout).map_err(Error::Utf8Error)
    }

    fn fetch_partition() -> Result<String, Error> {
        Self::fetch("/latest/meta-data/services/partition")
    }

    fn fetch_region() -> Result<String, Error> {
        Self::fetch("/latest/meta-data/placement/region")
    }

    fn fetch_role_name() -> Result<String, Error> {
        Self::fetch("/latest/meta-data/iam/security-credentials")
    }

    fn fetch_role_arn() -> Result<String, Error> {
        let profile_arn =
            serde_json::from_str::<IamInfo>(&Self::fetch("/latest/meta-data/iam/info")?)
                .and_then(|info| Ok(info.instance_profile_arn))
                .map_err(Error::ParseError)?;
        let role_name = Self::fetch_role_name()?;

        let role_arn = profile_arn
            .split(":")
            .map(|word| match word.find("instance-profile/") {
                Some(_) => format!("role/{}", role_name),
                None => word.to_string(),
            })
            .collect::<Vec<String>>()
            .join(":");
        Ok(role_arn)
    }

    fn fetch_creds() -> Result<SecurityCredentials, Error> {
        let creds_str = Self::fetch(
            format!(
                "/latest/meta-data/iam/security-credentials/{}",
                Self::fetch_role_name()?
            )
            .as_str(),
        )?;
        serde_json::from_str(creds_str.as_str()).map_err(Error::ParseError)
    }
}

fn get_with<F, R>(getter: F) -> Result<R, Error>
where
    F: FnOnce(&ImdsCache) -> R,
{
    let mut guard = IMDS_CACHE.lock().map_err(|_| Error::PoisonedLock)?;
    if guard.is_none() {
        guard.replace(ImdsCache::new()?);
    }
    Ok(guard
        .as_ref()
        .map(|cache| getter(cache))
        // Safe to unwrap due to the `replace` above.
        .unwrap())
}
