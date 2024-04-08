// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::{Arc, Mutex};

use lazy_static::lazy_static;
use log::warn;
use serde::Deserialize;
use serde_json;
use std::process::Command;

lazy_static! {
    static ref IMDS_CACHE: Arc<Mutex<Option<ImdsCache>>> = Arc::new(Mutex::new(None));
}

const INSTANCE_ROLE_ARN_TAG: &str = "InstanceRoleArn";

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
#[derive(Debug, Deserialize)]
pub struct IamRole {
    #[serde(rename = "Path")]
    #[serde(skip)]
    pub path: serde_json::Value,
    #[serde(rename = "RoleName")]
    #[serde(skip)]
    pub role_name: serde_json::Value,
    #[serde(rename = "RoleId")]
    #[serde(skip)]
    pub role_id: serde_json::Value,
    #[serde(rename = "Arn")]
    pub arn: String,
    #[serde(rename = "CreateDate")]
    #[serde(skip)]
    pub create_date: serde_json::Value,
    #[serde(rename = "AssumeRolePolicyDocument")]
    #[serde(skip)]
    pub assume_role_policy_document: serde_json::Value,
    #[serde(rename = "MaxSessionDuration")]
    #[serde(skip)]
    pub max_session_duration: serde_json::Value,
    #[serde(rename = "RoleLastUsed")]
    #[serde(skip)]
    pub role_last_used: serde_json::Value,
}

#[allow(non_snake_case)]
#[derive(Debug, Deserialize)]
pub struct IamRoleInfo {
    #[serde(rename = "Role")]
    pub role: IamRole,
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
        let token = Self::get_session_token()?;

        Ok(Self {
            partition: Self::fetch_partition(&token)?,
            region: Self::fetch_region(&token)?,
            role_arn: Self::fetch_role_arn(&token)?,
            creds: Self::fetch_creds(&token)?,
        })
    }

    fn get_session_token() -> Result<String, Error> {
        let args = [
            "-X",
            "PUT",
            "http://169.254.169.254/latest/api/token",
            "-H",
            "X-aws-ec2-metadata-token-ttl-seconds: 600",
        ];

        let output = Command::new("curl")
            .args(&args)
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

    fn fetch(key: &str, token: &str) -> Result<String, Error> {
        let url = format!("http://169.254.169.254{}", key);
        let header = format!("X-aws-ec2-metadata-token: {}", token);
        let output = Command::new("curl")
            .arg("-H")
            .arg(header)
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

    fn fetch_partition(token: &str) -> Result<String, Error> {
        Self::fetch("/latest/meta-data/services/partition", token)
    }

    fn fetch_region(token: &str) -> Result<String, Error> {
        Self::fetch("/latest/meta-data/placement/region", token)
    }

    fn fetch_instance_tag(token: &str, tag_key: &str) -> Result<String, Error> {
        Self::fetch(
            format!("/latest/meta-data/tags/instance/{}", tag_key).as_str(),
            token,
        )
    }

    fn fetch_role_name(token: &str) -> Result<String, Error> {
        Self::fetch("/latest/meta-data/iam/security-credentials", token)
    }

    fn fetch_role_arn(token: &str) -> Result<String, Error> {
        if let Ok(role_arn) = Self::fetch_instance_tag(token, INSTANCE_ROLE_ARN_TAG) {
            return Ok(role_arn);
        }

        let role_name = Self::fetch_role_name(token)?;

        let output = Command::new("aws")
            .arg("iam")
            .arg("get-role")
            .arg("--role-name")
            .arg(format!("{}", role_name))
            .output()
            .map_err(Error::IoError)?;
        // If error, fallback to use the IMDS info to get the IAM role arn.
        // Note: This logic would not work for IAM roles which include paths.
        if !output.status.success() {
            warn!("Cannot fetch IAM role arn using the AWS CLI iam get-role command. Falling back to using IMDS.");
            warn!("For IAM roles with paths included, please add the IAM policy permission for iam:GetRole as per documentation - https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-refapp.html.");
            let profile_arn =
                serde_json::from_str::<IamInfo>(&Self::fetch("/latest/meta-data/iam/info", token)?)
                    .and_then(|info| Ok(info.instance_profile_arn))
                    .map_err(Error::ParseError)?;

            let role_arn = profile_arn
                .split(":")
                .map(|word| match word.find("instance-profile/") {
                    Some(_) => format!("role/{}", role_name),
                    None => word.to_string(),
                })
                .collect::<Vec<String>>()
                .join(":");

            return Ok(role_arn);
        }

        let iam_role_info: IamRoleInfo =
            serde_json::from_str(&String::from_utf8(output.stdout).map_err(Error::Utf8Error)?)
                .map_err(Error::ParseError)?;

        Ok(iam_role_info.role.arn)
    }

    fn fetch_creds(token: &str) -> Result<SecurityCredentials, Error> {
        let creds_str = Self::fetch(
            format!(
                "/latest/meta-data/iam/security-credentials/{}",
                Self::fetch_role_name(token)?
            )
            .as_str(),
            token,
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
