// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use vtok_common::{config, defs, util};
use vtok_rpc::api::schema;
use vtok_rpc::api::schema::{ApiError, ApiOk, ApiRequest, ApiResponse};
use vtok_rpc::{Transport, TransportError};

use super::aws_ne;

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
        let request = self
            .transport
            .recv_request()
            .map_err(Error::TransportError)?;

        let response = request
            .validate_args()
            .map_err(ApiError::InvalidArgs)
            .and_then(|_| match request {
                ApiRequest::AddToken { token } => Self::add_token(token),
                ApiRequest::DescribeDevice => Self::describe_device(),
                ApiRequest::DescribeToken { label, pin } => Self::describe_token(label, pin),
                ApiRequest::RefreshToken {
                    label,
                    pin,
                    envelope_key,
                } => Self::refresh_token(label, pin, envelope_key),
                ApiRequest::RemoveToken { label, pin } => Self::remove_token(label, pin),
                ApiRequest::UpdateToken { .. } => Err(ApiError::Nyi),
            });

        self.transport
            .send_response(response)
            .map_err(Error::TransportError)
    }

    fn add_token(token: schema::Token) -> ApiResponse {
        let mut config = config::Config::load_rw().map_err(|_| ApiError::InternalError)?;

        // Check if the token label is already in use by another token.
        let dup = config
            .slots()
            .iter()
            .filter(|s| match s {
                None => false,
                Some(tok) => tok.label == token.label,
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

        let mut private_keys = Vec::new();
        for key in token.keys {
            private_keys.push(config::PrivateKey {
                pem: match token.envelope_key {
                    schema::EnvelopeKey::Kms {
                        ref region,
                        ref access_key_id,
                        ref secret_access_key,
                        ref session_token,
                    } => aws_ne::kms_decrypt(
                        region.as_bytes(),
                        access_key_id.as_bytes(),
                        secret_access_key.as_bytes(),
                        session_token.as_bytes(),
                        key.encrypted_pem.as_bytes(),
                    )
                    .map_err(|_| ApiError::AttestationFailed)
                    .and_then(|v| String::from_utf8(v).map_err(|_| ApiError::AttestationFailed))?,
                },
                encrypted_pem: key.encrypted_pem,
                id: key.id,
                label: key.label,
            })
        }

        free_slot.replace(config::Token {
            label: token.label,
            pin: token.pin,
            private_keys,
            expiry_ts: util::time::monotonic_secs() + defs::TOKEN_EXPIRY_SECS,
        });

        config.save().map_err(|_| ApiError::InternalError)?;

        Ok(ApiOk::None)
    }

    fn describe_device() -> ApiResponse {
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

        Ok(ApiOk::DeviceDescription(schema::DeviceDescription {
            free_slot_count,
            tokens,
        }))
    }

    fn describe_token(label: String, pin: String) -> ApiResponse {
        let config = config::Config::load_ro().map_err(|_| ApiError::InternalError)?;
        let token = config
            .slots()
            .iter()
            .filter_map(|slot| slot.as_ref().filter(|tok| tok.label == label))
            .next()
            .ok_or(ApiError::TokenNotFound)?;
        if token.pin != pin {
            return Err(ApiError::AccessDenied);
        }

        let token_desc = schema::TokenDescription {
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
        };

        Ok(ApiOk::TokenDescription(token_desc))
    }

    fn refresh_token(label: String, pin: String, envelope_key: schema::EnvelopeKey) -> ApiResponse {
        let mut config = config::Config::load_rw().map_err(|_| ApiError::InternalError)?;
        let slot = config
            .slots_mut()
            .iter_mut()
            .find(|s| match s {
                None => false,
                Some(tok) => tok.label == label,
            })
            .ok_or(ApiError::TokenNotFound)?;

        // It's safe to unwrap here, since the above find() ensures slot != None
        let mut token = slot.as_mut().unwrap();
        if token.pin != pin {
            return Err(ApiError::AccessDenied);
        }

        // Since all the keys in one token are encrypted via the same envelope, we only need to
        // successfully decrypt one key, in order to achieve attestation.
        token
            .private_keys
            .iter()
            .next()
            .ok_or(ApiError::EmptyToken)
            .and_then(|key| {
                match envelope_key {
                    schema::EnvelopeKey::Kms {
                        ref region,
                        ref access_key_id,
                        ref secret_access_key,
                        ref session_token,
                    } => {
                        aws_ne::kms_decrypt(
                            region.as_bytes(),
                            access_key_id.as_bytes(),
                            secret_access_key.as_bytes(),
                            session_token.as_bytes(),
                            key.encrypted_pem.as_bytes(),
                        )
                        .map_err(|_| ApiError::AttestationFailed)
                        .and_then(|v| String::from_utf8(v).map_err(|_| ApiError::AttestationFailed))
                        .ok()
                        .filter(|pem| pem == &key.pem)
                        .ok_or(ApiError::AttestationFailed)?;
                    }
                };
                Ok(())
            })?;
        token.expiry_ts = util::time::monotonic_secs() + defs::TOKEN_EXPIRY_SECS;

        config.save().map_err(|_| ApiError::InternalError)?;

        Ok(ApiOk::None)
    }

    fn remove_token(label: String, pin: String) -> ApiResponse {
        let mut config = config::Config::load_rw().map_err(|_| ApiError::InternalError)?;
        let slot = config
            .slots_mut()
            .iter_mut()
            .find(|s| match s {
                None => false,
                Some(tok) => tok.label == label,
            })
            .ok_or(ApiError::TokenNotFound)?;
        if let Some(tok) = slot {
            if tok.pin != pin {
                return Err(ApiError::AccessDenied);
            }
        }
        slot.take();

        config.save().map_err(|_| ApiError::InternalError)?;

        Ok(ApiOk::None)
    }
}
