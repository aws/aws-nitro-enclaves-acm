// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
mod mngtok;

use std::rc::Rc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use log::{error, info};
use nix::unistd;

use crate::config;
use crate::imds;
use crate::util;
use crate::{defs, gdata};
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
    PinGenerationError(std::io::Error),
    TokenError(mngtok::Error),
}

pub struct Agent {
    enclave: Rc<P11neEnclave>,
    tokens: Vec<ManagedToken>,
    sync_interval: Duration,
}

impl Agent {
    pub fn new(mut config: config::Config) -> Result<Self, Error> {
        let enclave = Rc::new(P11neEnclave::new(config.enclave).map_err(Error::EnclaveError)?);

        let swap_pin = util::generate_pkcs11_pin().map_err(Error::PinGenerationError)?;
        let tokens = config
            .tokens
            .drain(..)
            .filter_map(
                |conf| match ManagedToken::new(conf, enclave.clone(), swap_pin.clone()) {
                    Ok(tok) => Some(tok),
                    Err(e) => {
                        error!("Error creating managed token: {:?}", e);
                        None
                    }
                },
            )
            .collect();

        Ok(Self {
            enclave,
            tokens,
            sync_interval: Duration::from_secs(
                config
                    .sync_interval_secs
                    .unwrap_or(defs::DEFAULT_SYNC_INTERVAL_SECS),
            ),
        })
    }

    pub fn run(&mut self) -> Result<(), Error> {
        if !self.enclave.wait_boot() {
            return Err(Error::EnclaveBootTimeout);
        }

        let mut next_sync = Instant::now();

        loop {
            nix::sys::signal::kill(unistd::Pid::from_raw(self.enclave.pid()), None)
                .map_err(|_| Error::EnclaveDied)?;

            if next_sync <= Instant::now() {
                self.sync()?;
                next_sync += self.sync_interval;
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
                        .rpc(schema::ApiRequest::RemoveToken {
                            label: tok.label.clone(),
                            pin: tok.pin.clone(),
                        })
                        .map_err(Error::EnclaveError)?
                        .map_err(Error::RemoveTokenError)?;
                }
                Err(e) => return Err(Error::TokenError(e)),
                Ok(_) => (),
            }
        }

        self.tokens
            .retain(|tok| broken_list.iter().find(|l| **l == tok.label).is_none());

        Ok(())
    }
}
