#!/usr/bin/env bash
# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Setup $PATH for eVault deliverables
# Used for automated builds
EVAULT_INSTALL_DIR=/home/ec2-user/evault/bin
export PATH="$EVAULT_INSTALL_DIR:$PATH"
