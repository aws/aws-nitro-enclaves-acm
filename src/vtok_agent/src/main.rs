// Copyright 2020-2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
extern crate lazy_static;
extern crate log;
extern crate nix;
extern crate serde;
extern crate serde_json;
extern crate serde_yaml;
extern crate vtok_rpc;

mod agent;
mod config;
mod enclave;
mod imds;
mod logger;
mod ne;
mod util;

use log::{debug, info};
use nix::sys::signal;
use std::fmt;
use std::sync::atomic::Ordering;

pub mod defs {
    pub const RUN_DIR: &str = "/run/nitro_enclaves/acm";
    pub const P11_MODULE_NAME: &str = "p11ne";

    pub const SERVICE_NGINX: &str = "nginx";
    pub const SERVICE_HTTPD: &str = "httpd";
    pub const HTTPD_OVERRIDE_DATA: &str =
        "[Service]\nType=forking\nExecStart=\nExecStart=/usr/sbin/httpd $OPTIONS -k start\n";
    pub const HTTPD_OVERRIDE_DIR: &str = "/etc/systemd/system/httpd.service.d/";
    pub const HTTPD_OVERRIDE_FILE: &str = "/etc/systemd/system/httpd.service.d/httpd.conf";

    pub const DEFAULT_CONFIG_PATH: &str = "/etc/nitro_enclaves/acm.yaml";
    pub const DEFAULT_EIF_PATH: &str = "/usr/share/nitro_enclaves/p11ne/p11ne.eif";
    pub const DEFAULT_P11KIT_PORT: u32 = 9999;
    pub const DEFAULT_RPC_PORT: u32 = 10000;
    pub const DEFAULT_ENCLAVE_BOOT_TIMEOUT_MS: u64 = 5000;
    pub const DEFAULT_FORCE_START: bool = true;
    pub const DEFAULT_RELOAD_WAIT_MS: u64 = 1000;
    pub const DEFAULT_SYNC_INTERVAL_SECS: u64 = 600;
    pub const DEFAULT_TOKEN_REFRESH_INTERVAL_SECS: u64 = 12 * 3600;
    pub const DEFAULT_LOG_LEVEL: log::Level = log::Level::Info;
    pub const DEFAULT_LOG_TIMESTAMP: bool = false;
    pub const DEFAULT_ACM_BUCKET: &str = "prod";
    pub const DEFAULT_ATTESTATION_RETRY_COUNT: usize = 5;
    pub const DEFAULT_SERVICE: &str = SERVICE_NGINX;
}

pub mod gdata {
    use std::sync::atomic::AtomicBool;

    pub static EXIT_CONDITION: AtomicBool = AtomicBool::new(false);
}

#[derive(Debug)]
enum Error {
    AgentError(agent::Error),
    ConfigError(config::Error),
    SignalHandlerInstallError(nix::Error),
}

impl From<Error> for i32 {
    fn from(_other: Error) -> i32 {
        // NOTE: we could discriminate between errors here to provide a more specific
        // exit code.
        1
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // TODO: pretty-format error messages
        match self {
            Self::AgentError(e) => write!(f, "AgentError: {:?}", e),
            Self::ConfigError(e) => write!(f, "ConfigError: {:?}", e),
            Self::SignalHandlerInstallError(e) => write!(f, "SignalHandlerInstallError: {:?}", e),
        }
    }
}

extern "C" fn signal_handler(signo: std::os::raw::c_int) {
    match signo {
        nix::libc::SIGINT | nix::libc::SIGTERM => {
            info!("Setting exit condition");
            gdata::EXIT_CONDITION.store(true, Ordering::SeqCst);
        }
        nix::libc::SIGALRM => {
            debug!("Waking up");
        }
        _ => (),
    }
}

fn rusty_main() -> Result<(), Error> {
    let mut args = std::env::args();

    args.next();

    // TODO: get config file from args
    let mut config =
        config::Config::from_file(defs::DEFAULT_CONFIG_PATH).map_err(Error::ConfigError)?;

    log::set_boxed_logger(Box::new(logger::Logger::new(config.log.take())))
        .map(|()| log::set_max_level(log::LevelFilter::Debug))
        .unwrap_or_else(|e| eprintln!("Warning: failed to initialize logger: {:?}", e));

    // Install signal handlers
    let sa = signal::SigAction::new(
        signal::SigHandler::Handler(signal_handler),
        signal::SaFlags::empty(),
        signal::SigSet::empty(),
    );
    unsafe {
        signal::sigaction(signal::SIGINT, &sa).map_err(Error::SignalHandlerInstallError)?;
        signal::sigaction(signal::SIGTERM, &sa).map_err(Error::SignalHandlerInstallError)?;
    }

    agent::Agent::new(config)
        .and_then(|mut ag| ag.run())
        .map_err(Error::AgentError)
}

fn main() {
    match rusty_main() {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(i32::from(e))
        }
    }
}
