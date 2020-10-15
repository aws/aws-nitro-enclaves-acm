# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# This is a dev-time container, used to simulate the environment inside our
# targeted Amazon Linux 2 parent instance. I.e. only used for eVault development.

FROM amazonlinux:2

ARG USER
ARG USER_ID
ARG GROUP_ID
ARG RUST_TOOLCHAIN

RUN yum install -y \
    git \
    gnutls-utils \
    sudo

RUN mkdir -p /tmp/build
COPY setup.sh /tmp/build/
COPY install /tmp/build/install
RUN cd /tmp/build \
    && chmod +x setup.sh \
    && ./setup.sh --target devctr --rust-toolchain $RUST_TOOLCHAIN \
    && rm -rf /tmp/build

# Create dev-time user if it not already present
RUN [[ $(id -u) -eq $USER_ID ]] && exit 0; \
    groupadd -g $GROUP_ID "$USER"; \
    group_name=$(getent group $GROUP_ID | cut -d: -f1) \
    && useradd -u $USER_ID -d "/home/$USER" -g "$group_name" -s /bin/bash "$USER" \
    && chown -R "$USER:$group_name" "$HOME" \
    && echo "$USER ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Set up nitro-cli
RUN mkdir -p /var/log/nitro_enclaves \
    && chown $USER_ID:$GROUP_ID /var/log/nitro_enclaves
ENV NITRO_CLI_BLOBS=/opt/nitro_cli

ENV HOME="/home/$USER"
ENV PATH="$PATH:$HOME/.cargo/bin"
USER $USER
WORKDIR $HOME

# Install Rust
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain $RUST_TOOLCHAIN

CMD ["/bin/bash"]
