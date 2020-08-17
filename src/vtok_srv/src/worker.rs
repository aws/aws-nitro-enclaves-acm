// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use vtok_common::{config, defs, util};
use vtok_rpc::api::schema;
use vtok_rpc::api::schema::{ApiError, ApiRequest, ApiResponse};
use vtok_rpc::{Transport, TransportError};

#[derive(Debug)]
pub enum Error {
    TransportError(TransportError),
}

pub struct Worker<T: Transport> {
    transport: T,
}

impl<T> Worker<T>
where
    T: Transport,
{
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    pub fn run(&mut self) -> Result<(), Error> {
        macro_rules! respond {
            ($response:expr) => {{
                self.transport
                    .send_response($response)
                    .map_err(Error::TransportError)
            }};
        }

        let request = self
            .transport
            .recv_request()
            .map_err(Error::TransportError)?;

        request
            .validate_args()
            .or_else(|e| respond!(ApiResponse::<()>::Err(ApiError::InvalidArgs(e))))
            .and_then(|_| match request {
                ApiRequest::AddToken(args) => respond!(Self::add_token(args)),
                ApiRequest::DescribeDevice => respond!(Self::describe_device()),
                ApiRequest::DescribeToken(args) => respond!(Self::describe_token(args)),
                ApiRequest::RefreshToken(args) => respond!(Self::refresh_token(args)),
                ApiRequest::RemoveToken(args) => respond!(Self::remove_token(args)),
                ApiRequest::UpdateToken(_args) => {
                    respond!(schema::UpdateTokenResponse::Err(ApiError::Nyi))
                }
            })
    }

    fn add_token(args: schema::AddTokenArgs) -> schema::AddTokenResponse {
        let mut config = config::Config::load_rw().map_err(|_| ApiError::InternalError)?;

        // Check if the token label is already in use by another token.
        let dup = config
            .slots()
            .iter()
            .filter(|s| match s {
                None => false,
                Some(tok) => tok.label == args.token.label,
            })
            .count();
        if dup > 0 {
            return Err(ApiError::TokenLabelInUse);
        }

        // Find the first free slot.
        let free_slot = config
            .slots_mut()
            .iter_mut()
            .find(|s| s.is_none())
            .ok_or(ApiError::TooManyTokens)?;

        let private_keys = args
            .token
            .keys
            .iter()
            .map(|key| {
                // TODO: use envelope key to decript private keys.
                config::PrivateKey {
                    pem: key.encrypted_pem.clone(),
                    id: key.id,
                    label: key.label.clone(),
                }
            })
            .collect();

        free_slot.replace(config::Token {
            label: args.token.label,
            pin: args.token.pin,
            private_keys,
            expiry_ts: util::time::monotonic_secs() + defs::TOKEN_EXPIRY_SECS,
        });

        config.save().map_err(|_| ApiError::InternalError)?;

        Ok(())
    }

    fn describe_device() -> schema::DescribeDeviceResponse {
        let config = config::Config::load_ro().map_err(|_| ApiError::InternalError)?;
        let tokens: Vec<schema::TokenDescription> = config
            .slots()
            .iter()
            .filter_map(|slot| {
                slot.as_ref().and_then(|tok| {
                    Some(schema::TokenDescription {
                        label: tok.label.clone(),
                        ttl_secs: tok.expiry_ts.checked_sub(util::time::monotonic_secs())?,
                        keys: None,
                    })
                })
            })
            .collect();
        let free_slot_count = defs::DEVICE_MAX_SLOTS - tokens.len();
        Ok(schema::DeviceDescription {
            free_slot_count,
            tokens,
        })
    }

    fn describe_token(args: schema::DescribeTokenArgs) -> schema::DescribeTokenResponse {
        let config = config::Config::load_ro().map_err(|_| ApiError::InternalError)?;
        let token = config
            .slots()
            .iter()
            .filter_map(|slot| slot.as_ref().filter(|tok| tok.label == args.label))
            .next()
            .ok_or(ApiError::TokenNotFound)?;
        if token.pin != args.pin {
            return Err(ApiError::AccessDenied);
        }
        Ok(schema::TokenDescription {
            label: token.label.clone(),
            ttl_secs: token
                .expiry_ts
                .checked_sub(util::time::monotonic_secs())
                .unwrap_or(0),
            keys: Some(
                token
                    .private_keys
                    .iter()
                    .map(|key| schema::PrivateKeyDescription {
                        label: key.label.clone(),
                        id: key.id,
                    })
                    .collect(),
            ),
        })
    }

    fn refresh_token(args: schema::RefreshTokenArgs) -> schema::RefreshTokenResponse {
        let mut config = config::Config::load_rw().map_err(|_| ApiError::InternalError)?;
        let slot = config
            .slots_mut()
            .iter_mut()
            .find(|s| match s {
                None => false,
                Some(tok) => tok.label == args.label,
            })
            .ok_or(ApiError::TokenNotFound)?;

        // It's safe to unwrap here, since the above find() ensures slot != None
        let mut token = slot.as_mut().unwrap();
        if token.pin != args.pin {
            return Err(ApiError::AccessDenied);
        }

        // TODO: perform attestation
        //
        token.expiry_ts = util::time::monotonic_secs() + defs::TOKEN_EXPIRY_SECS;

        config.save().map_err(|_| ApiError::InternalError)?;

        Ok(())
    }

    fn remove_token(args: schema::RemoveTokenArgs) -> schema::RemoveTokenResponse {
        let mut config = config::Config::load_rw().map_err(|_| ApiError::InternalError)?;
        let slot = config
            .slots_mut()
            .iter_mut()
            .find(|s| match s {
                None => false,
                Some(tok) => tok.label == args.label,
            })
            .ok_or(ApiError::TokenNotFound)?;
        if let Some(tok) = slot {
            if tok.pin != args.pin {
                return Err(ApiError::AccessDenied);
            }
        }
        slot.take();

        config.save().map_err(|_| ApiError::InternalError)?;

        Ok(())
    }
}
