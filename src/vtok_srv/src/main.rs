// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

extern crate libc;
extern crate vtok_common;
extern crate vtok_rpc;

mod aws_ne;
mod worker;

use std::fmt;
use std::os::unix::net::UnixListener;
use std::time::Duration;

use vtok_common::{config, defs};
use vtok_rpc::api::schema;
use vtok_rpc::proto::Stream;
use vtok_rpc::HttpTransport;
use vtok_rpc::{Listener, VsockAddr, VsockListener};
use worker::Worker;

const USAGE: &str = r#"Nitro vToken database provisioning server
    Usage:
        vtoken-srv vsock <port>
        vtoken-srv unix <path>
"#;

#[derive(Debug)]
enum Error {
    ConfigError(config::Error),
    IoError(std::io::Error),
    UsageError,
    InitRandError,
    WorkerError(worker::Error),
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
            Self::ConfigError(e) => write!(f, "{:?}", e),
            Self::IoError(e) => write!(f, "{:?}", e),
            Self::UsageError => write!(f, "{}", USAGE),
            Self::InitRandError => write!(f, "[vToken] Cannot initialize eVault RNG"),
            Self::WorkerError(e) => write!(f, "{:?}", e),
        }
    }
}

fn handle_client<S: Stream>(stream: S) -> Result<(), Error> {
    // TODO: worker management (e.g. concurrency, jailing, etc).
    stream
        .set_read_timeout(Some(Duration::from_millis(defs::RPC_STREAM_TIMEOUT_MS)))
        .map_err(Error::IoError)?;
    stream
        .set_write_timeout(Some(Duration::from_millis(defs::RPC_STREAM_TIMEOUT_MS)))
        .map_err(Error::IoError)?;

    let xport = HttpTransport::new(stream, schema::API_URL);
    let mut worker = Worker::new(xport);
    worker.run().map_err(Error::WorkerError)
}

fn run_server<L: Listener>(listener: L) -> Result<(), Error> {
    config::Config::init_new().map_err(Error::ConfigError)?;
    println!("[vToken] Provisioning server is now running");

    loop {
        let client_result = listener
            .accept()
            .map_err(Error::IoError)
            .and_then(|stream| handle_client(stream));
        if let Err(e) = client_result {
            eprintln!("Error handling client connection: {:?}", e);
        }
    }
}

fn rusty_main() -> Result<(), Error> {
    let mut args = std::env::args();

    args.next();

    match (
        args.next().as_ref().map(|s| s.as_str()),
        args.next().as_ref().map(|s| s.as_str()),
    ) {
        (Some("vsock"), Some(port)) => {
            let port = port
                .parse::<std::os::raw::c_uint>()
                .map_err(|_| Error::UsageError)?;
            VsockListener::bind(VsockAddr::any_cid_with_port(port), 5)
                .map_err(Error::IoError)
                .and_then(|l| run_server(l))?;
        }
        (Some("unix"), Some(path)) => {
            UnixListener::bind(path)
                .map_err(Error::IoError)
                .and_then(|l| run_server(l))?;
        }
        (_, _) => return Err(Error::UsageError),
    };
    Ok(())
}

fn main() {
    match rusty_main() {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            eprintln!("[vToken] {}", e);
            std::process::exit(i32::from(e))
        }
    }
}
