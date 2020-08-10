// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use vtok_common::{config, defs, util};
use vtok_rpc::{Transport, TransportError};
use vtok_rpc::api::{ApiError, ApiRequest};
use vtok_rpc::api::schema;

#[derive(Debug)]
pub enum Error {
    TransportError(TransportError),
}

pub struct Worker<T: Transport> {
    transport: T,
}

impl<T> Worker<T> where T: Transport {

    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    pub fn run(&mut self) -> Result<(), Error> {
        let request = self
            .transport
            .recv_request()
            .map_err(Error::TransportError)?;

        let response = request
            .validate_args()
            .map_err(ApiError::InvalidArgs)
            .and_then(|_| match request {
                ApiRequest::AddToken(args) => Self::add_token(args),
                ApiRequest::RefreshToken(args) => Self::refresh_token(args),
                ApiRequest::RemoveToken(args) => Self::remove_token(args),
                ApiRequest::UpdateToken(_args) => Err(ApiError::Nyi),
            });

        self
            .transport
            .send_response(response)
            .map_err(Error::TransportError)?;

        Ok(())
    }

    fn add_token(args: schema::AddTokenArgs) -> schema::AddTokenResponse {
        let mut config = config::Config::load_rw()
            .map_err(|_| ApiError::InternalError)?;

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

        let private_keys = args.token.keys.iter().map(|key| {
            // TODO: use envelope key to decript private keys.
            config::PrivateKey {
                pem: key.encrypted_pem.clone(),
                id: key.id,
                label: key.label.clone(),
            }
        }).collect();

        free_slot.replace(config::Token {
            label: args.token.label,
            pin: args.token.pin,
            private_keys,
            expiry_ts: util::time::monotonic_secs() + defs::TOKEN_EXPIRY_SECS,
        });

        config.save().map_err(|_| ApiError::InternalError)?;

        Ok(())
    }

    fn refresh_token(args: schema::RefreshTokenArgs) -> schema::RefreshTokenResponse {
        let mut config = config::Config::load_rw()
            .map_err(|_| ApiError::InternalError)?;
        let slot = config
            .slots_mut()
            .iter_mut()
            .find(|s| match s {
                None => false,
                Some(tok) => tok.label == args.label
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
        let mut config = config::Config::load_rw()
            .map_err(|_| ApiError::InternalError)?;
        let slot = config
            .slots_mut()
            .iter_mut()
            .find(|s| match s {
                None => false,
                Some(tok) => tok.label == args.label
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
