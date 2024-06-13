// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use std::fmt::Write;
use std::fs::OpenOptions;
use std::io::Read;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use crate::gdata;
use nix::libc;

pub enum SleepError {
    UserExit,
}

#[derive(Debug)]
pub enum SystemdError {
    SendSignalError(nix::Error),
    ExecError(std::io::Error),
    StartError(Option<i32>),
    ParsePidError,
    ShowPidError(Option<i32>, String),
    OverrideError,
    ReloadError,
    StreamError(std::string::FromUtf8Error),
}

pub fn interruptible_sleep(dur: Duration) -> Result<(), SleepError> {
    let wake_time = Instant::now() + dur;
    loop {
        let now = Instant::now();
        if now >= wake_time {
            return Ok(());
        }
        let remaining = libc::timespec {
            tv_sec: (wake_time - now).as_secs() as libc::time_t,
            tv_nsec: (wake_time - now).subsec_nanos() as libc::c_long,
        };
        unsafe { libc::nanosleep(&remaining, std::ptr::null_mut()) };
        if gdata::EXIT_CONDITION.load(Ordering::SeqCst) {
            return Err(SleepError::UserExit);
        }
    }
}

pub fn generate_pkcs11_pin() -> Result<String, std::io::Error> {
    OpenOptions::new()
        .read(true)
        .open("/dev/urandom")
        .and_then(|mut file| {
            let mut buf = vec![0u8; 16];
            file.read_exact(buf.as_mut_slice())?;
            Ok(bytes_to_hex(buf.as_slice()))
        })
}

pub fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        // Pushing to a string should never fail, unless we're out of memory,
        // in which case it's ok to panic.
        write!(hex, "{:02x}", b).unwrap();
    }
    hex
}

pub fn create_dirs_for_file<P: AsRef<Path>>(file_path: P) -> Result<(), std::io::Error> {
    Path::new(file_path.as_ref())
        .parent()
        .ok_or(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("bad file path: {}", file_path.as_ref().display()),
        ))
        .and_then(|dir| std::fs::create_dir_all(dir))
}
