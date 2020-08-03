// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

extern crate vtok_rpc;

use std::fmt;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use vtok_rpc::ApiRequest;
use vtok_rpc::{HttpTransport, Transport};
use vtok_rpc::{VsockAddr, VsockStream};

const USAGE: &str = r#"Nitro vToken Tool
    Usage:
        nitro-vtoken vsock <cid> <port>
        nitro-vtoken unix <path>
"#;

enum Error {
    IoError(std::io::Error),
    TransportError(vtok_rpc::transport::Error),
    UsageError,
}

impl From<Error> for i32 {
    fn from(_other: Error) -> i32 {
        // NOTE: we could discriminate between errors here to provide a more specific
        // exit code.
        1
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // TODO: pretty-format error messages
        match self {
            Self::IoError(e) => write!(f, "{:?}", e),
            Self::UsageError => write!(f, "{}", USAGE),
            Self::TransportError(e) => write!(f, "{:?}", e),
        }
    }
}

fn run_client<S: Read + Write>(stream: S) -> Result<(), Error> {
    let mut xport = HttpTransport::new(stream, "/rpc/v1");
    xport
        .send_request(ApiRequest::Hello {
            sender: "TestClient".to_string(),
        })
        .map_err(Error::TransportError)?;
    let resp = xport.recv_response().map_err(Error::TransportError)?;
    println!("Test client got reponse: {:?}", resp);
    Ok(())
}

/// Parameters:
/// AF_VSOCK: <nitro-vtoken> "vsock" "16" "10000"
/// AF_UNIX:  <nitro-vtoken> "unix" "some/path"
fn rusty_main() -> Result<(), Error> {
    let mut args = std::env::args();

    args.next();

    match (
        args.next().as_ref().map(|s| s.as_str()),
        args.next().as_ref().map(|s| s.as_str()),
        args.next().as_ref().map(|s| s.as_str()),
    ) {
        (Some("vsock"), Some(cid), Some(port)) => {
            let cid = cid
                .parse::<std::os::raw::c_uint>()
                .map_err(|_| Error::UsageError)?;
            let port = port
                .parse::<std::os::raw::c_uint>()
                .map_err(|_| Error::UsageError)?;
            VsockStream::connect(VsockAddr { cid, port })
                .map_err(Error::IoError)
                .and_then(|s| run_client(s))?;
        }
        (Some("unix"), Some(path), None) => {
            UnixStream::connect(path)
                .map_err(Error::IoError)
                .and_then(|s| run_client(s))?;
        }
        _ => return Err(Error::UsageError),
    }

    // TODO: Lots of logic to add

    println!("Done");

    Ok(())
}

fn main() {
    match rusty_main() {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(i32::from(e))
        }
    }
}
