// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::process::Command;

/// The eVault enclave init
/// Spawns the eVault enclave main applications
/// - the random seeder
/// - the provisioning/rpc server
/// - the p11-kit server
fn main() {
    Command::new("vtok-rand")
        .spawn()
        .expect("random generator failed to start.")
        .wait()
        .expect("random generator exited with error.");
    Command::new("p11-kit")
        .args(&[
            "server",
            "-n",
            "vsock:port=9999",
            "--provider",
            "/usr/lib/libvtok_p11.so",
            "-f",
            "-v",
            "pkcs11:",
        ])
        .spawn()
        .expect("p11-kit server failed to start.");
    Command::new("vtok-srv")
        .args(&["vsock", "10000"])
        .spawn()
        .expect("provisioning server failed to start.")
        .wait() // Block here. If the provisioning server dies, terminate the enclave.
        .expect("provisioning server has exited.");
}
