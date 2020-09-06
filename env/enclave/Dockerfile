# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# This Docker file sets up the development environment for the eVault components
# that live inside the enclave.
# Note: this is not the container image used to generate the final enclave image,
#       but a somewhat dependency-heavy dev-time environment. The enclave image
#       source container will start from scratch, cherry-picking only its
#       required run-time dependencies from here.

FROM alpine:3.12

ARG USER
ARG USER_ID
ARG GROUP_ID
ARG RUST_TOOLCHAIN
ARG GITHUB_CREDS


# Force Rust dynamic linking against the Alpine-default musl libc.
ENV RUSTFLAGS="-C target-feature=-crt-static"

# Install system dependencies / packages.
RUN apk add \
    ca-certificates \
    cmake \
    g++ \
    gcc \
    git \
    go \
    p11-kit-server \
    perl \
    curl \
    make \
    automake \
    autoconf \
    linux-headers \
    shadow \
    sudo

# Only needed to build aws-lc
RUN apk add quilt --repository=http://dl-cdn.alpinelinux.org/alpine/edge/testing

RUN ln -s /usr/lib /usr/lib64

RUN mkdir -p /build
WORKDIR /build

# Build AWS libcrypto
# TODO: use a tag, once one becomes available.
ENV AWS_LC_VER=6eabe67472e5e3aa89341d365d5385c3eb6406eb
RUN git clone "https://github.com/awslabs/aws-lc.git" \
    && cd aws-lc \
    && git reset --hard $AWS_LC_VER \
    && cmake \
        -DCMAKE_PREFIX_PATH=/usr \
        -DCMAKE_INSTALL_PREFIX=/usr \
        -DBUILD_SHARED_LIBS=1 \
        -DBUILD_TESTING=0 \
        -B build \
    && cmake --build build/ --parallel $(nproc) --target crypto \
    && mv build/third_party/boringssl/crypto/libcrypto.so /usr/lib/ \
    && cp -rf third_party/boringssl/include/openssl /usr/include/ \
    && ldconfig /usr/lib

# AWS-S2N
ENV AWS_S2N_VER=v0.10.15
RUN git clone https://github.com/awslabs/s2n.git \
    && cd s2n \
    && git reset --hard $AWS_S2N_VER \
    && cmake \
        -DCMAKE_PREFIX_PATH=/usr \
        -DCMAKE_INSTALL_PREFIX=/usr \
        -DBUILD_SHARED_LIBS=1 \
        -DBUILD_TESTING=0 \
        -B build \
    && cmake --build build/ --parallel $(nproc) --target install

# AWS-C-COMMON
ENV AWS_C_COMMON_VER=v0.4.56
RUN git clone https://github.com/awslabs/aws-c-common.git \
    && cd aws-c-common \
    && git reset --hard $AWS_C_COMMON_VER \
    && cmake \
        -DCMAKE_PREFIX_PATH=/usr \
        -DCMAKE_INSTALL_PREFIX=/usr \
        -DBUILD_SHARED_LIBS=1 \
        -DBUILD_TESTING=0 \
        -B build \
    && cmake --build build/ --parallel $(nproc) --target install

# AWS-C-IO
ENV AWS_C_IO_VER=2fb7007483c270410c40c3aff8abdcaa36df8050
RUN git clone https://github.com/awslabs/aws-c-io.git \
    && cd aws-c-io \
    && git reset --hard $AWS_C_IO_VER \
    && cmake \
        -DUSE_VSOCK=1 \
        -DCMAKE_PREFIX_PATH=/usr \
        -DCMAKE_INSTALL_PREFIX=/usr \
        -DBUILD_SHARED_LIBS=1 \
        -DBUILD_TESTING=0 \
        -B build \
    && cmake --build build/ --parallel $(nproc) --target install

# AWS-C-COMPRESSION
ENV AWS_C_COMPRESSION_VER=v0.2.10
RUN git clone http://github.com/awslabs/aws-c-compression.git \
    && cd aws-c-compression \
    && git reset --hard $AWS_C_COMPRESSION_VER \
    && cmake \
        -DCMAKE_PREFIX_PATH=/usr \
        -DCMAKE_INSTALL_PREFIX=/usr \
        -DBUILD_SHARED_LIBS=1 \
        -DBUILD_TESTING=0 \
        -B build \
    && cmake --build build --parallel $(nproc) --target install

# AWS-C-HTTP
ENV AWS_C_HTTP_VER=v0.5.17
RUN git clone https://github.com/awslabs/aws-c-http.git \
    && cd aws-c-http \
    && git reset --hard $AWS_C_HTTP_VER \
    && cmake \
        -DCMAKE_PREFIX_PATH=/usr \
        -DCMAKE_INSTALL_PREFIX=/usr \
        -DBUILD_SHARED_LIBS=1 \
        -DBUILD_TESTING=0 \
        -B build \
    && cmake --build build --parallel $(nproc) --target install

# AWS-C-CAL
ENV AWS_C_CAL_VER=v0.2.7
RUN git clone https://github.com/awslabs/aws-c-cal.git \
    && cd aws-c-cal \
    && git reset --hard $AWS_C_CAL_VER \
    && cmake \
        -DCMAKE_PREFIX_PATH=/usr \
        -DCMAKE_INSTALL_PREFIX=/usr \
        -DBUILD_SHARED_LIBS=1 \
        -DBUILD_TESTING=0 \
        -B build \
    && cmake --build build --parallel $(nproc) --target install

# AWS-C-AUTH
ENV AWS_C_AUTH_VER=v0.4.2
RUN git clone https://github.com/awslabs/aws-c-auth.git \
    && cd aws-c-auth \
    && git reset --hard $AWS_C_AUTH_VER \
    && cmake \
        -DCMAKE_PREFIX_PATH=/usr \
        -DCMAKE_INSTALL_PREFIX=/usr \
        -DBUILD_SHARED_LIBS=1 \
        -DBUILD_TESTING=0 \
        -B build \
    && cmake --build build --parallel $(nproc) --target install

# JSON-C library
ENV JSON_C_VER=json-c-0.14-20200419
RUN git clone https://github.com/json-c/json-c.git \
    && cd json-c \
    && git reset --hard $JSON_C_VER \
    && cmake \
        -DCMAKE_PREFIX_PATH=/usr \
        -DCMAKE_INSTALL_PREFIX=/usr \
        -DBUILD_SHARED_LIBS=1 \
        -DBUILD_TESTING=0 \
        -B build \
    && cmake --build build --parallel $(nproc) --target install

# Install Rust
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain $RUST_TOOLCHAIN

# NSM LIB
# TODO: use a tag, once we have one.
ENV AWS_NE_NSM_API_VER=e3a1dfe9fb9d5354d7006c9738d62dbf7e086f53
RUN git clone "https://$GITHUB_CREDS@github.com/aws/aws-nitro-enclaves-nsm-api.git" \
    && cd aws-nitro-enclaves-nsm-api \
    && PATH="$PATH:/root/.cargo/bin" cargo build --release \
    && mv target/release/libnsm.so /usr/lib/ \
    && mv target/release/nsm.h /usr/include/

# AWS Nitro Enclaves SDK
# TODO: use a tag, once we have one.
ENV AWS_NE_SDK_VER=711c3f1b7b638c5864e695d3760bcf12c3fdc2f3
RUN git clone "https://$GITHUB_CREDS@github.com/aws/aws-nitro-enclaves-sdk-c" \
    && cd aws-nitro-enclaves-sdk-c \
    && cmake \
        -DCMAKE_PREFIX_PATH=/usr \
        -DCMAKE_INSTALL_PREFIX=/usr \
        -DBUILD_SHARED_LIBS=1 \
        -DBUILD_TESTING=0 \
        -B build \
    && cmake --build build --target install --parallel $(nproc)

# Set up dev user
RUN groupadd -g $GROUP_ID $USER; \
    group_name=$(getent group $GROUP_ID | cut -d: -f1) \
    && useradd -u $USER_ID -m -d "/home/$USER" -g "$group_name" -s /bin/sh $USER \
    && echo "$USER ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers \
    && mv /root/.cargo "/home/$USER/.cargo" \
    && mv /root/.rustup "/home/$USER/.rustup" \
    && chown -R "$USER:$group_name" "/home/$USER"

USER $USER
ENV HOME=/home/$USER
ENV PATH="$HOME/.cargo/bin:$PATH"

CMD ["/bin/sh"]
