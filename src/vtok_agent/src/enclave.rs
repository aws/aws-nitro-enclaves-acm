// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use log::{info, warn};
use nix::libc;
use nix::sys::signal;
use nix::unistd;
use std::fs::OpenOptions;
use std::io::Write;
use std::process::Command;
use std::sync::atomic::Ordering;
use std::time::Duration;

use super::defs;
use super::ne;
use crate::{config, gdata};
use vtok_rpc::api::schema;
use vtok_rpc::{HttpTransport, Transport, VsockAddr, VsockStream};

#[derive(Debug)]
pub enum Error {
    NitroCliError(ne::Error),
    P11KitSetupError(std::io::Error),
    RpcConnectError(std::io::Error),
    RpcTransportError(vtok_rpc::TransportError),
    SystemdExecError(std::io::Error),
    VsockProxyError(Option<i32>),
}

pub struct P11neEnclave {
    cid: u32,
    pid: i32,
    boot_timeout: std::time::Duration,
    rpc_port: u32,
}

impl P11neEnclave {
    pub fn new(enclave_config: config::Enclave) -> Result<Self, Error> {
        let eri = ne::run_enclave(
            enclave_config
                .image_path
                .as_ref()
                .map(|s| s.as_str())
                .unwrap_or(defs::DEFAULT_EIF_PATH),
            enclave_config.cpu_count,
            enclave_config.memory_mib,
        )
        .map_err(Error::NitroCliError)?;

        info!("Setting up p11-kit config");
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(format!(
                "/etc/pkcs11/modules/{}.module",
                defs::P11_MODULE_NAME
            ))
            .and_then(|mut file| {
                file.write(
                    format!(
                        "remote:vsock:cid={};port={}\nmodule:{}\n",
                        eri.enclave_cid,
                        enclave_config
                            .p11kit_port
                            .unwrap_or(defs::DEFAULT_P11KIT_PORT),
                        defs::P11_MODULE_NAME,
                    )
                    .as_bytes(),
                )
            })
            .map_err(Error::P11KitSetupError)?;

        info!("Restarting vsock proxy");
        Command::new("systemctl")
            .args(&["restart", "nitro-enclaves-vsock-proxy"])
            .status()
            .map_err(Error::SystemdExecError)
            .and_then(|status| {
                if status.success() {
                    Ok(())
                } else {
                    Err(Error::VsockProxyError(status.code()))
                }
            })?;

        Ok(Self {
            // TODO: replace these rudimentary casts with proper checks/conversions.
            cid: eri.enclave_cid as u32,
            pid: eri.process_id as i32,
            boot_timeout: std::time::Duration::from_millis(
                enclave_config
                    .boot_timeout_ms
                    .unwrap_or(defs::DEFAULT_ENCLAVE_BOOT_TIMEOUT_MS),
            ),
            rpc_port: enclave_config.rpc_port.unwrap_or(defs::DEFAULT_RPC_PORT),
        })
    }

    pub fn wait_boot(&self) -> bool {
        let mut left = Some(self.boot_timeout);
        let poll_us = 100_000_u32;
        while left.is_some() {
            if let Ok(Ok(_)) = self.rpc(&schema::ApiRequest::DescribeDevice) {
                return true;
            }
            unsafe {
                libc::usleep(poll_us);
            }
            if gdata::EXIT_CONDITION.load(Ordering::SeqCst) {
                return false;
            }
            left = left.and_then(|x| x.checked_sub(Duration::from_micros(u64::from(poll_us))));
        }
        false
    }

    pub fn pid(&self) -> i32 {
        self.pid
    }

    pub fn rpc(&self, request: &schema::ApiRequest) -> Result<schema::ApiResponse, Error> {
        VsockStream::connect(VsockAddr {
            cid: self.cid,
            port: self.rpc_port,
        })
        .map_err(Error::RpcConnectError)
        .map(|stream| HttpTransport::new(stream, schema::API_URL))
        .and_then(|mut xport| {
            xport
                .send_request(request)
                .map_err(Error::RpcTransportError)?;
            xport.recv_response().map_err(Error::RpcTransportError)
        })
    }
}

impl Drop for P11neEnclave {
    fn drop(&mut self) {
        info!("Killing enclave pid={}", self.pid());
        signal::kill(unistd::Pid::from_raw(self.pid()), signal::Signal::SIGTERM)
            .unwrap_or_default();
        info!("Cleaning up p11kit config");
        std::fs::remove_file(format!(
            "/etc/pkcs11/modules/{}.module",
            defs::P11_MODULE_NAME
        ))
        .unwrap_or_else(|err| warn!("Cleanup error: {:?}", err));
    }
}
