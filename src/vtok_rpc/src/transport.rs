// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::io::{BufRead, BufReader, Read, Write};

use super::api::schema::{ApiRequest, ApiResponse};

#[derive(Debug)]
pub enum Error {
    BadUrl,
    IoError(std::io::Error),
    MsgLen,
    ParseError,
    SerdeError(serde_json::error::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

/// RPC transport trait. Implementors will have to provide the methods for send / receiving
/// requests and responses. The implementation will likely wrap an underlying stream
/// (i.e. Read + Write), and handle message / datagram traffic.
pub trait Transport {
    /// Receive an RPC request.
    fn recv_request(&mut self) -> Result<ApiRequest>;
    /// Send an RPC request.
    fn send_request(&mut self, req: &ApiRequest) -> Result<()>;
    /// Receive an RPC response.
    fn recv_response(&mut self) -> Result<ApiResponse>;
    /// Send an RPC response.
    fn send_response(&mut self, resp: &ApiResponse) -> Result<()>;
}

/// RPC transport implementation via a super-simple subset of HTTP.
///
/// Requests and responses are serialized as HTTP messages, with JSON bodies.
/// They always travel the underlying stream sequantially (i.e. once a request is sent,
/// the caller must always read its corresponding response before submitting a new request).
///
/// All API-related information is exchanged via the message (JSON) body. I.e. HTTP handling
/// stops at the transport layer, so methods, URLs, status codes, do not change across RPC
/// messages. I.e:
/// - the method is always POST;
/// - the URL is always `self.url`;
/// - the response status is always "200 OK".
///
///
/// Example:
///
/// ----- REQUEST -----
/// POST /rpc/v1.0 HTTP/1.1
/// Content-Type: application/json
/// Content-Length: 35
///
/// {"Hello": {"sender": "TestClient"}}
/// ----- REQUEST -----
///
/// ----- RESPONSE -----
/// 200 OK
/// Content-Type: application/json
/// Content-Length: 39
///
/// {"Hello": {"Ok": "Hello, TestClient!"}}
/// ----- RESPONSE -----
pub struct HttpTransport<S: Read + Write> {
    /// The (connected) data stream between caller and callee.
    stream: S,
    /// The HTTP URL that the RPC server responds to. This can be used to versionize the API
    /// (e.g. /rpc/v1).
    url: &'static str,
}

/// The HTTP headers our RPC transport is interested in.
struct HttpHeaders {
    content_length: usize,
}

impl<S: Read + Write> HttpTransport<S> {
    /// Maximum size (in bytes) of an HTTP message headers section.
    const MAX_HDR_LEN: usize = 1 * 1024;
    /// Maximum size (in bytes) of an HTTP message body.
    const MAX_BODY_LEN: usize = 64 * 1024;

    /// Create a new HTTP transport object from a connected stream.
    /// Args:
    ///   - stream: the connected `Read + Write` stream;
    ///   - url: the HTTP URL (can be used to provide API versioning);
    ///          Note: all requests use the same URL, since the actual API endpoint call is
    ///          part of the JSON body.
    pub fn new(stream: S, url: &'static str) -> Self {
        Self { stream, url }
    }

    /// Read / parse the HTTP headers (that we recognize) from the provided buffered reader.
    fn read_headers<R: BufRead>(reader: &mut R) -> Result<HttpHeaders> {
        let mut content_length = None;

        loop {
            let mut ln = String::new();
            reader.read_line(&mut ln).map_err(Error::IoError)?;
            let ln = ln.as_str().trim();

            if ln.len() == 0 {
                break;
            }

            let mut iter = ln.split(": ");
            match (iter.next(), iter.next()) {
                (Some("Content-Length"), Some(len)) => {
                    let len = len.parse::<usize>().map_err(|_| Error::ParseError)?;
                    content_length = Some(len);
                }
                (Some("Content-Type"), Some("application/json")) => (),
                _ => return Err(Error::ParseError),
            }
        }

        match content_length {
            Some(content_length) => {
                if content_length > Self::MAX_BODY_LEN {
                    return Err(Error::MsgLen);
                }
                Ok(HttpHeaders { content_length })
            }
            _ => Err(Error::ParseError),
        }
    }
}

impl<S: Read + Write> Transport for HttpTransport<S> {
    fn recv_request(&mut self) -> Result<ApiRequest> {
        // This is a nifty trick to get line-by-line input, while also limitting the amount
        // of data we can read from the wire:
        // Read::take(N) will return a Take struct (itself and implementor of Read), that will
        // be limited at reading at most N bytes. We can then pass this Take to BufReader, and
        // get a limited buffered reader.
        // However both Take and BufReader need to own the underlying Read implementor. To get
        // around ownership issues, and since our BufReader only needs to survive reading
        // exactly one message, we can rely on the fact that if R: Read, then &mut R: Read,
        // and use a Take(&mut self.stream).
        let mut reader = BufReader::new((&mut self.stream).take(Self::MAX_HDR_LEN as u64));
        let mut ln = String::new();
        reader.read_line(&mut ln).map_err(Error::IoError)?;
        let mut iter = ln.as_str().trim().split_whitespace();
        match (iter.next(), iter.next(), iter.next()) {
            (Some("POST"), Some(url), Some("HTTP/1.1")) => {
                if url != self.url {
                    return Err(Error::BadUrl);
                }
            }
            _ => return Err(Error::ParseError),
        }

        Self::read_headers(&mut reader).and_then(|h| {
            reader.get_mut().set_limit(h.content_length as u64);
            let mut buf = vec![0u8; h.content_length];
            reader
                .read_exact(buf.as_mut_slice())
                .map_err(Error::IoError)?;
            serde_json::from_slice(buf.as_slice()).map_err(Error::SerdeError)
        })
    }

    fn send_request(&mut self, request: &ApiRequest) -> Result<()> {
        let body = serde_json::to_vec(&request).map_err(Error::SerdeError)?;
        self.stream
            .write(
                format!(
                    "POST {} HTTP/1.1\r\n\
                    Content-Type: application/json\r\n\
                    Content-Length: {}\r\n\
                    \r\n",
                    self.url,
                    body.len()
                )
                .as_bytes(),
            )
            .map_err(Error::IoError)?;
        self.stream.write(body.as_slice()).map_err(Error::IoError)?;
        Ok(())
    }

    fn recv_response(&mut self) -> Result<ApiResponse> {
        let mut reader = BufReader::new((&mut self.stream).take(Self::MAX_HDR_LEN as u64));
        let mut ln = String::new();
        reader.read_line(&mut ln).map_err(Error::IoError)?;
        let mut iter = ln.as_str().trim().split_whitespace();
        match (iter.next(), iter.next()) {
            (Some("200"), Some("OK")) => (),
            _ => return Err(Error::ParseError),
        }
        Self::read_headers(&mut reader).and_then(|h| {
            reader.get_mut().set_limit(h.content_length as u64);
            let mut buf = vec![0u8; h.content_length];
            reader
                .read_exact(buf.as_mut_slice())
                .map_err(Error::IoError)?;
            serde_json::from_slice(buf.as_slice()).map_err(Error::SerdeError)
        })
    }

    fn send_response(&mut self, response: &ApiResponse) -> Result<()> {
        let body = serde_json::to_vec(&response).map_err(Error::SerdeError)?;
        self.stream
            .write(
                format!(
                    "200 OK\r\n\
                    Content-Type: application/json\r\n\
                    Content-Length: {}\r\n\
                    \r\n",
                    body.len()
                )
                .as_bytes(),
            )
            .map_err(Error::IoError)?;
        self.stream.write(body.as_slice()).map_err(Error::IoError)?;
        Ok(())
    }
}
