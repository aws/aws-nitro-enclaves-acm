// Copyright 2020-2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
mod httpd;
mod mngtok;
mod nginx;

use super::defs;
use crate::config;
use crate::gdata;
use crate::imds;
use crate::util::{
    interruptible_sleep, is_service_running, service_restart, service_start,
    SystemdError,
};
use crate::{enclave, enclave::P11neEnclave};
use log::{debug, error, info, warn};
use mngtok::{ManagedService, ManagedToken};
use nix::{sys::signal, unistd};
use std::collections::HashSet;
use std::fs::{create_dir_all, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::rc::Rc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use vtok_rpc::api::schema;

#[derive(Debug)]
pub enum Error {
    EnclaveBootTimeout,
    EnclaveDied,
    EnclaveError(enclave::Error),
    RemoveTokenError(schema::ApiError),
    ImdsError(imds::Error),
    TokenError(mngtok::Error),
}

pub struct Agent {
    enclave: Rc<P11neEnclave>,
    tokens: Vec<ManagedToken>,
    options: config::Options,
}

#[derive(Debug, Hash, Eq, PartialEq)]
pub enum PostSyncAction {
    RestartNginx,
}

impl Agent {
    pub fn new(mut config: config::Config) -> Result<Self, Error> {
        let enclave = Rc::new(P11neEnclave::new(config.enclave).map_err(Error::EnclaveError)?);
        let service =
            ManagedService::from_str(&config.options.service).map_err(Error::TokenError)?;
        let tokens = config
            .tokens
            .drain(..)
            .filter_map(
                |conf| match ManagedToken::new(conf, enclave.clone(), service) {
                    Ok(tok) => Some(tok),
                    Err(e) => {
                        error!("Error creating managed token: {:?}", e);
                        None
                    }
                },
            )
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

            interruptible_sleep(Duration::from_secs(1)).unwrap_or_default();
            if gdata::EXIT_CONDITION.load(Ordering::SeqCst) {
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
                Err(mngtok::Error::KeyMaterialDbFetchError(_, _))
                | Err(mngtok::Error::KeyMaterialDbParseError(_))
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
                        .remove_token(tok.label.clone(), tok.pin.clone())
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
        info!(
            "Service: {} | Force_Start: {} | Reload: {} | Sync: {}",
            options.service,
            options.force_start,
            options.reload_wait_ms,
            options.sync_interval_secs
        );
        match self {
            Self::RestartNginx => Self::restart_nginx(options.reload_wait_ms),
        }
    }

    fn restart_nginx(wait_ms: u64) {
        info!("Restarting NGINX.");

        if let Ok(pid) = is_service_running("nginx.service") {
            debug!("Sending SIGWINCH to PID={}", pid);
            signal::kill(unistd::Pid::from_raw(pid), signal::Signal::SIGWINCH).unwrap_or_else(
                |err| {
                    error!("Error sending SIGWINCH: {:?}", err);
                },
            );

            std::thread::sleep(Duration::from_millis(wait_ms));
        } else {
            info!("NGINX service is not running");
        }

        service_restart("nginx.service").unwrap_or_else(|err| {
            error!("Unable to restart NGINX: {:?}", err);
        });
    }
}