// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use nsm_driver::{nsm_exit, nsm_init, nsm_process_request};
use nsm_io::{Request, Response};
use std::fmt;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::os::unix::io::AsRawFd;

/// Number of bytes to seed
const DEV_SEED_CNT: usize = 512;

enum Error {
    InitNsmError,
    NsmCommError,
    InitRandError,
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
        match self {
            Self::InitNsmError => write!(f, "[vToken] Cannot initialize the NSM driver."),
            Self::NsmCommError => write!(f, "[vToken] Cannot get entropy from the NSM driver."),
            Self::InitRandError => write!(f, "[vToken] Cannot initialize eVault enclave CRNG."),
        }
    }
}

/// Function for seeding initial eVault RNG
/// TODO: The SDK shall handle this
fn seed_random(total: usize) -> Result<(), Error> {
    let nsm_fd = nsm_init();
    if nsm_fd < 0 {
        return Err(Error::InitNsmError);
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
                return Err(Error::NsmCommError);
            }
        }
    }
    Ok(nsm_exit(nsm_fd))
}

fn main() {
    match seed_random(DEV_SEED_CNT) {
        Ok(()) => {
            println!("[vToken] urand initialized via NSM");
            std::process::exit(0)
        }
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1)
        }
    }
}
