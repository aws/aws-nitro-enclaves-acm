# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
FROM fedora:latest

ARG USER
ARG USER_ID
ARG GROUP_ID
ARG RUST_TOOLCHAIN=stable

ENV HOME=/home/$USER
ENV PATH="$HOME/.cargo/bin:$PATH"

# Install system dependencies / packages.
#
RUN dnf -y install \
        cmake \
        g++ \
        gcc \
        git \
        gnutls-utils \
        golang \
        make \
        nginx \
        opensc \
        automake \
        openssl-pkcs11 \
        p11-kit-server \
        openssl-devel \
        libtasn1-devel \
        libffi-devel \
        sudo \
        diffutils \
        procps \
        jq \
        which

# Configure nginx.
#
ADD nginx.conf /etc/nginx/nginx.conf
ADD index.html /var/www/index.html


# Make sure the current user (the one building this container) also shows up in the container.
# Since we'll be bind-mouting the sources into the running container, this will make file
# permission management so much easier.
#
RUN groupadd -g $GROUP_ID $USER; \
        group_name=$(getent group $GROUP_ID | cut -d: -f1) \
        && useradd -u $USER_ID -d "$HOME" -g "$group_name" -s /bin/bash $USER \
        && chown -R "$USER_NAME:$group_name" $HOME \
        && echo "$USER ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers


# Build / install BoringSSL from source.
RUN mkdir -p /tmp \
    && cd /tmp \
    && git clone -b chromium-stable https://github.com/google/boringssl.git boringssl \
    && cd boringssl \
    && cmake -DBUILD_SHARED_LIBS=1 \
    && make -j$(getconf _NUMPROCESSORS_ONLN) crypto \
    && mv crypto/libcrypto.so /usr/lib64/libcrypto_boring.so \
    && ldconfig \
    && rm -rf /tmp/boringssl


USER $USER

# Install Rust
#
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain "$RUST_TOOLCHAIN" \
    && rustup component add rustfmt \
    && cargo install bindgen

RUN ln -s /vtok $HOME/vtok
WORKDIR /vtok

CMD ["/bin/bash"]
