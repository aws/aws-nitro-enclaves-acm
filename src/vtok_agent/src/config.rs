// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use serde::{Deserialize, Serialize};
use serde_yaml;

#[derive(Debug)]
pub enum Error {
    IoError(std::io::Error),
    YamlError(serde_yaml::Error),
}

#[derive(Debug, Deserialize, Serialize)]
pub enum Target {
    NginxStanza {
        path: String,
        user: Option<String>,
        group: Option<String>,
        force_start: Option<bool>,
    },
}

#[derive(Debug, Deserialize, Serialize)]
pub enum Source {
    Acm {
        certificate_arn: String,
        bucket: Option<String>,
    },
    FileDb {
        path: String,
    },
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Token {
    pub label: String,
    pub pin: Option<String>,
    pub source: Source,
    pub target: Option<Target>,
    pub refresh_interval_secs: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Enclave {
    pub cpu_count: usize,
    pub memory_mib: u64,
    pub image_path: Option<String>,
    pub boot_timeout_ms: Option<u64>,
    pub p11kit_port: Option<u32>,
    pub rpc_port: Option<u32>,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Log {
    pub level: LogLevel,
    pub enable_timestamp: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    pub enclave: Enclave,
    pub tokens: Vec<Token>,
    pub sync_interval_secs: Option<u64>,
    pub log: Option<Log>,
}

impl Config {
    pub fn from_file<P: AsRef<std::path::Path>>(path: P) -> Result<Self, Error> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .open(path)
            .map_err(Error::IoError)?;
        serde_yaml::from_reader(file).map_err(Error::YamlError)
    }
}

impl From<LogLevel> for log::Level {
    fn from(src: LogLevel) -> Self {
        match src {
            LogLevel::Error => log::Level::Error,
            LogLevel::Warn => log::Level::Warn,
            LogLevel::Info => log::Level::Info,
            LogLevel::Debug => log::Level::Debug,
            LogLevel::Trace => log::Level::Trace,
        }
    }
}
