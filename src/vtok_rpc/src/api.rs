// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod schema {

    pub use v1::*;

    pub mod v1 {
        use super::super::validators;
        use serde::{Deserialize, Serialize};

        /// The RPC URL used for the evault API.
        /// Note: this can and should be used to versionize the API.
        pub const API_URL: &str = "/rpc/v1";

        /// An RPC API request, holding the API endpoint (i.e. procedure) and its input params.
        ///
        /// This type will provide serialization (and deserialization) facilities, so that it can be
        /// sent over an RPC transport.
        #[derive(Debug, Deserialize, Serialize)]
        pub enum ApiRequest {
            /// Add a new token. The new token will be inserted into the first free slot.
            ///
            /// Returns:
            /// - `ApiOk::None` on success;
            /// - `ApiError::TooManyTokens` if there are no more free slots left;
            /// - `ApiError::TokenLabelInUse` if the token label is already being used by
            ///    another token;
            /// - `ApiError::{InvalidArgs, InternalError}`.
            AddToken {
                /// The parameters of the new token.
                token: Token,
            },

            /// Get a high-level description of the evault device, including active tokens
            /// and the current number of free slots.
            ///
            /// Returns:
            /// - `ApiOk::DeviceDescription` on success;
            /// - `ApiError::InternalError`.
            ///
            DescribeDevice,

            /// Get a detailed description of a specific token.
            /// The caller will need to provide the correct PIN in order to access the token.
            ///
            /// Returns:
            /// - `ApiOk::TokenDescription` on success;
            /// - `ApiError::AccessDenied` if the incorrect PIN is supplied;
            /// - `ApiError::TokenNotFound` if the supplied label doesn't match any active token;
            /// - `ApiError::InternalError`.
            DescribeToken {
                /// Label identified the token to describe.
                label: String,
                /// The PIN granting access to the token to describe.
                pin: String,
            },

            /// Refresh a specific token, by going through the attestation process again, using the
            /// newly supplied credentials.
            ///
            /// Returns:
            /// - `ApiOk::None` on success;
            /// - `ApiError::AccessDenied` if the incorrect PIN is supplied;
            /// - `ApiError::TokenNotFound` if the supplied label doesn't match any active token;
            /// - `ApiError::{InvalidArgs, InternalError}`.
            RefreshToken {
                /// Label of the token to be refreshed.
                label: String,
                /// The PIN granting access to the token identified by `label`.
                pin: String,
                /// The envelope key specification, used to perform enclave attestation / decrypt
                /// the token private keys.
                envelope_key: EnvelopeKey,
            },

            /// Remove a specific token from the evault device.
            ///
            /// Returns:
            /// - `ApiOk::None` on success;
            /// - `ApiError::TokenNotFound` if the supplied label doesn't match any active token;
            /// - `ApiError::AccessDenied` if the incorect PIN is supplied;
            /// - `ApiError::InternalError`.
            RemoveToken {
                /// Label of the token to remove.
                label: String,
                /// The PIN granting access to the target token.
                pin: String,
            },

            /// Update a specific token in-place.
            ///
            /// NYI
            UpdateToken {
                label: String,
                pin: String,
                token: Token,
            },
        }

        /// An RPC API response, holding the result type for every API endpoint described by
        /// `ApiRequest`.
        ///
        /// This type will provide serialization (and deserialization) facilities, so that it can be
        /// sent over an RPC transport.
        pub type ApiResponse = std::result::Result<ApiOk, ApiError>;

        #[derive(Debug, Deserialize, Serialize)]
        pub enum ApiOk {
            None,
            DeviceDescription(DeviceDescription),
            TokenDescription(TokenDescription),
        }

        #[derive(Debug, Deserialize, Serialize)]
        pub enum ApiError {
            AccessDenied,
            EmptyToken,
            InvalidArgs(validators::Error),
            InternalError,
            TokenLabelInUse,
            TokenNotFound,
            TooManyTokens,
            TokenProvisioningFailed,
            TokenRefreshFailed,
            TokenKeyDecodingFailed,
            KmsDecryptFailed,
        }

        #[derive(Debug, Deserialize, Serialize)]
        pub enum EnvelopeKey {
            Kms {
                region: String,
                access_key_id: String,
                secret_access_key: String,
                session_token: String,
            },
        }

        #[derive(Debug, Deserialize, Serialize)]
        pub struct PrivateKey {
            pub encrypted_pem_b64: String,
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
        pub struct PrivateKeyDescription {
            pub label: String,
            pub id: u8,
            pub uri: String,
        }

        #[derive(Debug, Deserialize, Serialize)]
        pub struct TokenDescription {
            pub label: String,
            pub slot_id: usize,
            pub ttl_secs: u64,
            pub keys: Option<Vec<PrivateKeyDescription>>,
        }

        #[derive(Debug, Deserialize, Serialize)]
        pub struct DeviceDescription {
            pub free_slot_count: usize,
            pub tokens: Vec<TokenDescription>,
        }
    }
}

pub mod validators {
    use super::schema;
    use serde::{Deserialize, Serialize};
    use std::collections::HashSet;
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

    impl schema::ApiRequest {
        pub fn validate_args(&self) -> Result<(), Error> {
            match self {
                Self::AddToken { token } => {
                    validate_token(&token)?;
                }
                Self::DescribeDevice => (),
                Self::DescribeToken { label, pin } => {
                    validate_token_pin(pin.as_str())?;
                    validate_token_label(label.as_str())?;
                }
                Self::UpdateToken { label, pin, token } => {
                    validate_token_pin(pin.as_str())?;
                    validate_token_label(label.as_str())?;
                    validate_token(&token)?;
                }
                Self::RefreshToken { label, pin, .. } => {
                    validate_token_pin(pin.as_str())?;
                    validate_token_label(label.as_str())?;
                }
                Self::RemoveToken { label, pin } => {
                    validate_token_pin(pin.as_str())?;
                    validate_token_label(label.as_str())?;
                }
            }
            Ok(())
        }
    }
}
