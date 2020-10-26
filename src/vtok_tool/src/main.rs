// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

extern crate serde;
extern crate serde_json;
extern crate vtok_rpc;

use std::collections::HashMap;
use std::fmt;
use std::os::unix::net::UnixStream;

use vtok_rpc::api::schema;
use vtok_rpc::{HttpTransport, Transport};
use vtok_rpc::{VsockAddr, VsockStream};

const USAGE: &str = r#"p11ne client
    Usage:
        p11ne-client <command> [<global options>] [<command options>]

    Global options:
        --server <address>
            [REQUIRED]
            Address used to connect to the p11ne server, using the format
            [vsock:CID:PORT | unix:PATH].
            vsock example (say CID=3 and port=5252): --server vsock:3:5252
            Unix sockets example: --server unix:/tmp/p11ne-rpc.sock

        --help
            Show this usage message.

    Commands:

        raw-rpc
            Perform a raw remote procedure call. This provides a low-level interface
            to the p11ne RPC server.
            A raw (json-serialized) API request is read from STDIN, sent to the p11ne
            RPC server, and the response is written to STDOUT, also in its raw,
            json-serialized form.

        help
            Show this usage message.
"#;

enum Error {
    IoError(std::io::Error),
    TransportError(vtok_rpc::transport::Error),
    UsageError(String),
    SerdeError(serde_json::Error),
}

enum ServerAddr {
    Vsock(VsockAddr),
    Unix(String),
}

enum CliOption {
    Server(ServerAddr),
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
            Self::SerdeError(_) => write!(f, "internal error"),
            Self::UsageError(s) => write!(f, "Error: {}.\nUse --help for help.", s),
            Self::TransportError(e) => write!(f, "{:?}", e),
        }
    }
}

fn parse_server_addr(addr_str: &str) -> Result<ServerAddr, Error> {
    let mut iter = addr_str.split(":");
    match (iter.next(), iter.next(), iter.next()) {
        (Some("unix"), Some(path), None) => Ok(ServerAddr::Unix(path.to_string())),
        (Some("vsock"), Some(cid_str), Some(port_str)) => {
            match (
                cid_str.parse::<std::os::raw::c_uint>(),
                port_str.parse::<std::os::raw::c_uint>(),
            ) {
                (Ok(cid), Ok(port)) => Ok(ServerAddr::Vsock(VsockAddr { cid, port })),
                _ => Err(Error::UsageError(format!(
                    "invalid server addr: {}",
                    addr_str
                ))),
            }
        }
        _ => Err(Error::UsageError(format!(
            "invalid server addr: {}",
            addr_str
        ))),
    }
}

fn cmd_raw_rpc<I: Iterator<Item = String>>(mut arg_iter: I) -> Result<(), Error> {
    let mut cli_opts = HashMap::new();

    while let Some(word) = arg_iter.next() {
        match word.as_str() {
            "--server" => {
                let addr = arg_iter
                    .next()
                    .ok_or(Error::UsageError(format!("invalid server addr")))
                    .and_then(|addr| parse_server_addr(addr.as_str()))?;
                cli_opts.insert(word, CliOption::Server(addr));
            }
            _ => return Err(Error::UsageError(format!("unexpected argument: {}", word))),
        }
    }

    let server_addr = match cli_opts.get("--server") {
        Some(CliOption::Server(addr)) => addr,
        _ => return Err(Error::UsageError(format!("missing server address"))),
    };

    fn do_raw_rpc<T: Transport>(mut transport: T) -> Result<(), Error> {
        let request = serde_json::from_reader(std::io::stdin())
            .map_err(|_| Error::UsageError(format!("Invalid RPC request")))?;
        transport
            .send_request(request)
            .map_err(Error::TransportError)?;
        let response = transport.recv_response().map_err(Error::TransportError)?;

        serde_json::to_writer(std::io::stdout(), &response).map_err(Error::SerdeError)?;

        Ok(())
    }

    match server_addr {
        ServerAddr::Unix(path) => UnixStream::connect(path)
            .map_err(Error::IoError)
            .map(|stream| HttpTransport::new(stream, schema::API_URL))
            .and_then(|xport| do_raw_rpc(xport)),
        ServerAddr::Vsock(addr) => VsockStream::connect(*addr)
            .map_err(Error::IoError)
            .map(|stream| HttpTransport::new(stream, schema::API_URL))
            .and_then(|xport| do_raw_rpc(xport)),
    }
}

/// Usage:
/// AF_VSOCK: p11ne-client "vsock" "10000"
/// AF_UNIX:  p11ne-client "unix" "some/path"
fn rusty_main() -> Result<(), Error> {
    let mut args = std::env::args();

    // Skip executable name.
    args.next();

    match args.next().as_ref().map(|s| s.as_str()) {
        Some("raw-rpc") => cmd_raw_rpc(args),
        Some("help") | Some("--help") | Some("-h") => {
            println!("{}", USAGE);
            Ok(())
        }
        Some(cmd) => Err(Error::UsageError(format!("invalid command: {}", cmd))),
        None => Err(Error::UsageError("missing command".to_string())),
    }
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
