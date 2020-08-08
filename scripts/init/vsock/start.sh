#!/usr/bin/env bash
# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# The vToken enclave initialization script over AF_VSOCK transport

P11_SERVER_PORT="9999"
PROVISIONING_PORT="10000"
PROVISIONING_CID="4294967295" # VMADDR_CID_ANY
VTOK_MODULE="/usr/lib/libvtok_p11.so"

# Start the provisioning server
vtok-srv vsock $PROVISIONING_CID $PROVISIONING_PORT &

# Start the p11-kit server
p11-kit server -n vsock:port=$P11_SERVER_PORT --provider $VTOK_MODULE -f -v pkcs11:
