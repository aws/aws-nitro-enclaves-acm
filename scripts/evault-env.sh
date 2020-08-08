#!/usr/bin/env bash
# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Setup $PATH for eVault deliverables
# Default boot-time setup used for AL2 images
USER=$(whoami)
EVAULT_INSTALL_DIR=/home/$USER/evault/bin
export PATH="$EVAULT_INSTALL_DIR:$PATH"
