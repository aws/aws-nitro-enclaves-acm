// Copyright 2020-2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use std::fmt::Write;
use std::fs::OpenOptions;
use std::io::Read;
use std::path::Path;
use std::process::Command;
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

pub fn is_service_running(service_name: &str) -> Result<i32, SystemdError> {
    Command::new("systemctl")
        .args(&["show", "--property=MainPID", service_name.clone()])
        .output()
        .map_err(SystemdError::ExecError)
        .and_then(|output| {
            if !output.status.success() {
                return Err(SystemdError::ShowPidError(
                    output.status.code(),
                    String::from_utf8_lossy(output.stderr.as_slice()).to_string(),
                ));
            }
            String::from_utf8(output.stdout)
                .map_err(SystemdError::StreamError)
                .and_then(|line| {
                    line.as_str()
                        .trim()
                        .rsplit("=")
                        .next()
                        .ok_or(SystemdError::ParsePidError)
                        .and_then(|pid_str| {
                            pid_str
                                .parse::<i32>()
                                .map_err(|_| SystemdError::ParsePidError)
                        })
                })
        })
}

fn service_exec(arg1: &str, arg2: &str) -> Result<(), SystemdError> {
    Command::new("systemctl")
        .args(&[arg1.clone(), arg2.clone()])
        .status()
        .map_err(SystemdError::ExecError)
        .and_then(|status| {
            if !status.success() {
                Err(SystemdError::StartError(status.code()))
            } else {
                Ok(())
            }
        })
}

pub fn reload_systemd_daemon() -> Result<(), SystemdError> {
    Command::new("systemctl")
        .args(&["daemon-reload"])
        .status()
        .map_err(SystemdError::ExecError)
        .and_then(|status| {
            if !status.success() {
                Err(SystemdError::StartError(status.code()))
            } else {
                Ok(())
            }
        })
}

pub fn service_start(service_name: &str) -> Result<(), SystemdError> {
    service_exec("start", service_name)
}

pub fn service_restart(service_name: &str) -> Result<(), SystemdError> {
    service_exec("restart", service_name)
}
