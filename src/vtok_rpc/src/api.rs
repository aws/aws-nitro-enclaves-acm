// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub enum ApiError {
    AccessDenied,
    InvalidArgs(validators::Error),
    InternalError,
    TokenLabelInUse,
    TokenNotFound,
    TooManyTokens,
    // TODO: remove this NYI error once it's not needed anymore.
    Nyi,
}

pub mod schema {
    use serde::{Deserialize, Serialize};
    use super::ApiResponse;

    #[derive(Debug, Deserialize, Serialize)]
    pub enum EnvelopeKey {
        KmsId(String),
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct PrivateKey {
        pub encrypted_pem: String,
        pub id: u8,
        pub label: String,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct Token {
        pub label: String,
        pub pin: String,
        pub envelope_key: EnvelopeKey,
        pub keys: Vec<PrivateKey>,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct AddTokenArgs {
        pub token: Token,
    }
    pub type AddTokenResponse = ApiResponse<()>;

    #[derive(Debug, Deserialize, Serialize)]
    pub struct RefreshTokenArgs {
        pub label: String,
        pub pin: String,
        pub aws_id: String,
        pub aws_secret: String,
    }
    pub type RefreshTokenResponse = ApiResponse<()>;

    #[derive(Debug, Deserialize, Serialize)]
    pub struct RemoveTokenArgs {
        pub label: String,
        pub pin: String,
    }
    pub type RemoveTokenResponse = ApiResponse<()>;

    #[derive(Debug, Deserialize, Serialize)]
    pub struct UpdateTokenArgs {
        pub label: String,
        pub pin: String,
        pub token: Token,
    }
    pub type UpdateTokenResponse = ApiResponse<()>;

}

/// An RPC API request, holding the API endpoint (i.e. procedure) and its input params.
///
/// This type will provide serialization (and deserialization) facilities, so that it can be
/// sent over an RPC transport.
#[derive(Debug, Deserialize, Serialize)]
pub enum ApiRequest {
    AddToken(schema::AddTokenArgs),
    RefreshToken(schema::RefreshTokenArgs),
    RemoveToken(schema::RemoveTokenArgs),
    UpdateToken(schema::UpdateTokenArgs),
}

/// An RPC API response, holding the result type for every API endpoint described by
/// `ApiRequest`.
///
/// This type will provide serialization (and deserialization) facilities, so that it can be
/// sent over an RPC transport.
pub type ApiResponse<T> = Result<T, ApiError>;

pub mod validators {
    use std::collections::HashSet;
    use serde::{Deserialize, Serialize};
    use super::schema;
    use vtok_common::defs;

    #[derive(Debug, Deserialize, Serialize)]
    pub enum Error {
        DuplicateKeyId(u8),
        DuplicateKeyLabel(String),
        LabelTooLong,
        LabelTooShort,
        PinTooLong,
        PinTooShort,
    }

    fn validate_token_pin(pin: &str) -> Result<(), Error> {
        if pin.len() < defs::TOKEN_MIN_PIN_LEN {
            return Err(Error::PinTooShort);
        }
        if pin.len() > defs::TOKEN_MAX_PIN_LEN {
            return Err(Error::PinTooLong);
        }
        Ok(())
    }

    fn validate_token_label(label: &str) -> Result<(), Error> {
        if label.len() < defs::TOKEN_MIN_LABEL_LEN {
            return Err(Error::LabelTooShort);
        }
        if label.len() > defs::TOKEN_MAX_LABEL_LEN {
            return Err(Error::LabelTooLong);
        }
        Ok(())
    }

    fn validate_token(token: &schema::Token) -> Result<(), Error> {
        validate_token_pin(token.pin.as_str())?;
        validate_token_label(token.label.as_str())?;
        let mut ids = HashSet::new();
        let mut labels = HashSet::new();
        for k in token.keys.iter() {
            if !ids.insert(k.id) {
                return Err(Error::DuplicateKeyId(k.id));
            }
            if !labels.insert(k.label.as_str()) {
                return Err(Error::DuplicateKeyLabel(k.label.clone()));
            }
        }
        Ok(())
    }

    impl super::ApiRequest {
        pub fn validate_args(&self) -> Result<(), Error> {
            match self {
                Self::AddToken(args) => {
                    validate_token(&args.token)?;
                }
                Self::UpdateToken(args) => {
                    validate_token_pin(args.pin.as_str())?;
                    validate_token_label(args.label.as_str())?;
                    validate_token(&args.token)?;
                }
                Self::RefreshToken(args) => {
                    validate_token_pin(args.pin.as_str())?;
                    validate_token_label(args.label.as_str())?;
                }
                Self::RemoveToken(args) => {
                    validate_token_pin(args.pin.as_str())?;
                    validate_token_label(args.label.as_str())?;
                }
            }
            Ok(())
        }
    }
}
