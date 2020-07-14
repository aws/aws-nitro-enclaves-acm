use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub enum ApiError {}

pub type ApiResult<T> = Result<T, ApiError>;

/// An RPC API request, holding the API endpoint (i.e. procedure) and its input params.
///
/// This type will provide serialization (and deserialization) facilities, so that it can be
/// sent over an RPC transport.
#[derive(Debug, Deserialize, Serialize)]
pub enum ApiRequest {
    Hello { sender: String },
}

/// An RPC API response, holding the result type for every API endpoint described by
/// `ApiRequest`.
///
/// This type will provide serialization (and deserialization) facilities, so that it can be
/// sent over an RPC transport.
#[derive(Debug, Deserialize, Serialize)]
pub enum ApiResponse {
    Hello(ApiResult<String>),
}
