// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
mod mngtok;

use std::collections::HashSet;
use std::process::Command;
use std::rc::Rc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use log::{debug, error, info, warn};
use nix::{sys::signal, unistd};

use crate::config;
use crate::gdata;
use crate::imds;
use crate::{enclave, enclave::P11neEnclave};
use mngtok::ManagedToken;
use vtok_rpc::api::schema;

#[derive(Debug)]
pub enum Error {
    EnclaveBootTimeout,
    EnclaveDied,
    EnclaveError(enclave::Error),
    RemoveTokenError(schema::ApiError),
    ImdsError(imds::Error),
    SendSignalError(nix::Error),
    SystemdExecError(std::io::Error),
    SystemdParsePidError,
    SystemdShowPidError(Option<i32>, String),
    SystemdStartNginxError(Option<i32>),
    Utf8Error(std::string::FromUtf8Error),
    TokenError(mngtok::Error),
}

pub struct Agent {
    enclave: Rc<P11neEnclave>,
    tokens: Vec<ManagedToken>,
    options: config::Options,
}

#[derive(Hash, Eq, PartialEq)]
pub enum PostSyncAction {
    ReloadNginx,
}

impl Agent {
    pub fn new(mut config: config::Config) -> Result<Self, Error> {
        let enclave = Rc::new(P11neEnclave::new(config.enclave).map_err(Error::EnclaveError)?);

        let tokens = config
            .tokens
            .drain(..)
            .filter_map(|conf| match ManagedToken::new(conf, enclave.clone()) {
                Ok(tok) => Some(tok),
                Err(e) => {
                    error!("Error creating managed token: {:?}", e);
                    None
                }
            })
            .collect();

        debug!("Global options: {:?}", &config.options);

        Ok(Self {
            enclave,
            tokens,
            options: config.options,
        })
    }

    pub fn run(&mut self) -> Result<(), Error> {
        if !self.enclave.wait_boot() {
            return Err(Error::EnclaveBootTimeout);
        }

        let mut next_sync = Instant::now();
        let sync_interval = Duration::from_secs(self.options.sync_interval_secs);

        loop {
            nix::sys::signal::kill(unistd::Pid::from_raw(self.enclave.pid()), None)
                .map_err(|_| Error::EnclaveDied)?;

            if next_sync <= Instant::now() {
                self.sync()?;
                next_sync += sync_interval;
            }

            unistd::sleep(1);

            if gdata::EXIT_CONDITION.load(Ordering::SeqCst) {
                info!("Shutting down");
                return Ok(());
            }
        }
    }

    fn sync(&mut self) -> Result<(), Error> {
        let mut broken_list = Vec::new();
        let mut post_actions = HashSet::new();

        imds::invalidate_cache().map_err(Error::ImdsError)?;

        for tok in self.tokens.iter_mut() {
            info!("Syncing token {}", tok.label.as_str());
            match tok.sync() {
                // TODO: tidy up and be more verbose
                Err(mngtok::Error::AcmDbFetchError(_, _))
                | Err(mngtok::Error::AcmDbParseError(_))
                | Err(mngtok::Error::FileDbError(_))
                | Err(mngtok::Error::FileDbParseError(_)) => {
                    error!("Broken token: {}", tok.label.as_str());
                    broken_list.push(tok.label.clone());
                }
                Err(mngtok::Error::AddTokenError(schema::ApiError::KmsDecryptFailed)) => {
                    error!("Attestation failed for new token {}.", tok.label.as_str());
                    broken_list.push(tok.label.clone());
                }
                Err(mngtok::Error::RefreshTokenError(schema::ApiError::KmsDecryptFailed)) => {
                    error!(
                        "Attestation failed for token {}. Releasing",
                        tok.label.as_str()
                    );
                    broken_list.push(tok.label.clone());
                    self.enclave
                        .rpc(&schema::ApiRequest::RemoveToken {
                            label: tok.label.clone(),
                            pin: tok.pin.clone(),
                        })
                        .map_err(Error::EnclaveError)?
                        .map_err(Error::RemoveTokenError)?;
                }
                Err(e) => return Err(Error::TokenError(e)),
                Ok(None) => (),
                Ok(Some(act)) => {
                    post_actions.insert(act);
                }
            }
        }

        // Run post-sync actions
        post_actions
            .drain()
            .map(|act| act.execute(&self.options))
            .count();

        // Remove broken tokens
        self.tokens
            .retain(|tok| broken_list.iter().find(|l| **l == tok.label).is_none());

        Ok(())
    }
}

impl PostSyncAction {
    fn execute(&self, options: &config::Options) {
        match self {
            Self::ReloadNginx => {
                Self::reload_nginx(options.nginx_force_start, options.nginx_reload_wait_ms)
            }
        }
    }

    fn reload_nginx(force_start: bool, wait_ms: u64) {
        info!("Reloading NGINX config");
        Command::new("systemctl")
            .args(&["show", "--property=MainPID", "nginx.service"])
            .output()
            .map_err(Error::SystemdExecError)
            .and_then(|output| {
                if !output.status.success() {
                    return Err(Error::SystemdShowPidError(
                        output.status.code(),
                        String::from_utf8_lossy(output.stderr.as_slice()).to_string(),
                    ));
                }
                String::from_utf8(output.stdout)
                    .map_err(Error::Utf8Error)
                    .and_then(|line| {
                        line.as_str()
                            .trim()
                            .rsplit("=")
                            .next()
                            .ok_or(Error::SystemdParsePidError)
                            .and_then(|pid_str| {
                                pid_str
                                    .parse::<i32>()
                                    .map_err(|_| Error::SystemdParsePidError)
                            })
                    })
            })
            .and_then(|pid| match (pid, force_start) {
                (0, true) => {
                    info!("NGINX is not running. Starting it now.");
                    Command::new("systemctl")
                        .args(&["start", "nginx.service"])
                        .status()
                        .map_err(Error::SystemdExecError)
                        .and_then(|status| {
                            if !status.success() {
                                Err(Error::SystemdStartNginxError(status.code()))
                            } else {
                                Ok(())
                            }
                        })
                }
                (0, false) => {
                    warn!(
                        "Unable to reload NGINX: it isn't running and force starting is disabled"
                    );
                    Ok(())
                }
                (pid, _) => {
                    debug!("Sending SIGUSR2 to PID={}", pid);
                    signal::kill(unistd::Pid::from_raw(pid), signal::Signal::SIGUSR2)
                        .map_err(Error::SendSignalError)?;
                    debug!("Sending SIGWINCH to PID={}", pid);
                    signal::kill(unistd::Pid::from_raw(pid), signal::Signal::SIGWINCH)
                        .map_err(Error::SendSignalError)?;
                    debug!("Sleeping to allow NGINX to process live update.");
                    std::thread::sleep(Duration::from_millis(wait_ms));
                    debug!("Sending SIGQUIT to PID={}", pid);
                    signal::kill(unistd::Pid::from_raw(pid), signal::Signal::SIGQUIT)
                        .map_err(Error::SendSignalError)?;
                    Ok(())
                }
            })
            .unwrap_or_else(|err| {
                error!("Unable to reload NGINX: {:?}", err);
            });
    }
}
