// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

extern crate libc;
extern crate nsm_io;
extern crate vtok_rpc;

use nsm_driver::{nsm_exit, nsm_init, nsm_process_request};
use nsm_io::{Request, Response};
use std::fmt;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixListener;
use vtok_rpc::{ApiRequest, ApiResponse};
use vtok_rpc::{HttpTransport, Transport};
use vtok_rpc::{Listener, VsockAddr, VsockListener};

const USAGE: &str = r#"Nitro vToken database provisioning server
    Usage:
        vtoken-srv vsock <port>
        vtoken-srv unix <path>
"#;

const DEV_SEED_CNT: usize = 512;

enum Error {
    IoError(std::io::Error),
    UsageError,
    InitRandError,
    TransportError(vtok_rpc::transport::Error),
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
            Self::InitRandError => write!(f, "[vToken] Cannot initialize eVault RNG"),
            Self::TransportError(e) => write!(f, "{:?}", e),
        }
    }
}

/// Function for seeding initial eVault RNG
/// TODO: The SDK shall handle this or add it as stand-alone call in NSM lib
fn seed_random(total: usize) -> Result<(), Error> {
    let nsm_fd = nsm_init();
    if nsm_fd < 0 {
        return Err(Error::InitRandError);
    }

    let dev_file = File::open("/dev/random").map_err(|_| Error::InitRandError)?;
    let ifd = dev_file.as_raw_fd();
    let mut bw = BufWriter::new(dev_file);
    let mut count: usize = 0;
    while count < total {
        match nsm_process_request(nsm_fd, Request::GetRandom) {
            Response::GetRandom { random } => {
                bw.write_all(&random).map_err(|_| Error::InitRandError)?;
                count += random.len();
                // The crate::libc does not have RNDADDTOENTCNT. Use the raw ioctl number
                let ioctl_rnd_add = 0x40045201;
                let bits: i32 = (random.len() * 8) as i32;
                let ret = unsafe {
                    // Safe because all input params are on the stack
                    libc::ioctl(ifd, ioctl_rnd_add, &bits)
                };
                if ret < 0 {
                    nsm_exit(nsm_fd);
                    return Err(Error::InitRandError);
                }
            }
            _ => {
                nsm_exit(nsm_fd);
                return Err(Error::InitRandError);
            }
        }
    }
    Ok(nsm_exit(nsm_fd))
}

fn run_server<L: Listener>(listener: L) -> Result<(), Error> {
    println!("[vToken] Provisioning server is now running");
    loop {
        let stream = listener.accept().map_err(Error::IoError)?;

        // TODO: Add vtok_rpc logic

        let mut xport = HttpTransport::new(stream, "/rpc/v1");
        let req = xport.recv_request().map_err(Error::TransportError)?;
        println!("[vToken] Server got request: {:?}", req);
        let resp = match req {
            ApiRequest::Hello { sender } => ApiResponse::Hello(Ok(format!("Hello, {}!", sender))),
        };
        xport.send_response(resp).map_err(Error::TransportError)?;
    }
}

/// Parameters:
/// AF_VSOCK: <vtoken-srv> "vsock" "4294967295" "10000"
/// AF_UNIX:  <vtoken-srv> "unix" "some_path"
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
    match seed_random(DEV_SEED_CNT) {
        Ok(()) => println!("[vToken] urand initialized via NSM"),
        _ => {
            // Not a hard error. Just post a message.
            eprintln!("[vToken] urand not initialized")
        }
    }

    match rusty_main() {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            eprintln!("[vToken] {}", e);
            std::process::exit(i32::from(e))
        }
    }
}
