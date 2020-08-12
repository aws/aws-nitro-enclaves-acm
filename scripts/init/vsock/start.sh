#!/usr/bin/env bash
# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -u

# The eVault enclave initialization script
P11_KIT_BIN="p11-kit"
VTOK_RAND_BIN="vtok-rand"
VTOK_SRV_BIN="vtok-srv"
P11_SERVER_PORT="9999"
PROVISIONING_PORT="10000"
PROVISIONING_CID="4294967295" # VMADDR_CID_ANY
VTOK_MODULE="/usr/lib/libvtok_p11.so"

# Seed the CRNG
"$VTOK_RAND_BIN"
if [ $? -ne 0 ]; then
    exit 1
fi

# Start the provisioning server
"$VTOK_SRV_BIN" vsock $PROVISIONING_CID $PROVISIONING_PORT &
if [ $? -ne 0 ]; then
    exit 1
fi

# Start the p11-kit server
"$P11_KIT_BIN" server -n vsock:port=$P11_SERVER_PORT --provider $VTOK_MODULE -f -v pkcs11:
if [ $? -ne 0 ]; then
    exit 1
fi
