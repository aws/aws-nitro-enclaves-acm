# Copyright 2020-2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# This Docker file sets up the development environment for the eVault components
# that live inside the enclave.
# Note: this is not the container image used to generate the final enclave image,
#       but a somewhat dependency-heavy dev-time environment. The enclave image
#       source container will start from scratch, cherry-picking only its
#       required run-time dependencies from here.

FROM public.ecr.aws/docker/library/alpine:3.16

ARG USER
ARG USER_ID
ARG GROUP_ID
ARG RUST_TOOLCHAIN
ARG CTR_HOME

# Force Rust dynamic linking against the Alpine-default musl libc.
ENV RUSTFLAGS="-C target-feature=-crt-static"

# Install system dependencies / packages.
RUN apk add \
    p11-kit-server \
    ca-certificates \
    cmake \
    g++ \
    gcc \
    git \
    go \
    perl \
    curl \
    make \
    linux-headers \
    shadow \
    sudo

RUN ln -s /usr/lib /usr/lib64

RUN mkdir -p /build
WORKDIR /build

# Build AWS libcrypto
ENV AWS_LC_VER="v1.12.0"
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
    && mv build/crypto/libcrypto.so /usr/lib/ \
    && cp -rf include/openssl /usr/include/ \
    && ldconfig /usr/lib

# AWS-S2N
ENV AWS_S2N_VER="v1.3.46"
RUN git clone https://github.com/aws/s2n-tls.git \
    && cd s2n-tls \
    && git reset --hard $AWS_S2N_VER \
    && cmake \
        -DCMAKE_PREFIX_PATH=/usr \
        -DCMAKE_INSTALL_PREFIX=/usr \
        -DBUILD_SHARED_LIBS=1 \
        -DBUILD_TESTING=0 \
        -B build \
    && cmake --build build/ --parallel $(nproc) --target install

# AWS-C-COMMON
ENV AWS_C_COMMON_VER="v0.8.0"
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

# AWS-C-SDKUTILS
ENV AWS_C_SDKUTILS_VER="v0.1.2"
RUN git clone https://github.com/awslabs/aws-c-sdkutils \
    && cd aws-c-sdkutils \
    && git reset --hard $AWS_C_SDKUTILS_VER \
    && cmake \
        -DCMAKE_PREFIX_PATH=/usr \
        -DCMAKE_INSTALL_PREFIX=/usr \
        -DBUILD_SHARED_LIBS=1 \
        -DBUILD_TESTING=0 \
        -B build \
    && cmake --build build/ --parallel $(nproc) --target install

# AWS-C-CAL
ENV AWS_C_CAL_VER="v0.5.18"
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

# AWS-C-IO
ENV AWS_C_IO_VER="v0.11.0"
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
ENV AWS_C_COMPRESSION_VER="v0.2.14"
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
ENV AWS_C_HTTP_VER="v0.6.19"
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

# AWS-C-AUTH
ENV AWS_C_AUTH_VER="v0.6.15"
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
ENV JSON_C_VER="json-c-0.16-20220414"
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
ENV AWS_NE_NSM_API_VER="v0.4.0"
RUN git clone "https://github.com/aws/aws-nitro-enclaves-nsm-api" \
    && cd aws-nitro-enclaves-nsm-api \
    && git reset --hard $AWS_NE_NSM_API_VER \
    && PATH="$PATH:/root/.cargo/bin" cargo build --release -p nsm-lib \
    && mv target/release/libnsm.so /usr/lib/ \
    && mv target/release/nsm.h /usr/include/

# AWS Nitro Enclaves SDK
ENV AWS_NE_SDK_VER="v0.4.1"
RUN git clone "https://github.com/aws/aws-nitro-enclaves-sdk-c" \
    && cd aws-nitro-enclaves-sdk-c \
    && git reset --hard $AWS_NE_SDK_VER \
    && cmake \
        -DCMAKE_PREFIX_PATH=/usr \
        -DCMAKE_INSTALL_PREFIX=/usr \
        -DBUILD_SHARED_LIBS=1 \
        -DBUILD_TESTING=0 \
        -B build \
    && cmake --build build --target install --parallel $(nproc)

# Set up dev user
RUN [ $USER_ID -eq 0 ] && exit 0; \
    groupadd -g $GROUP_ID $USER; \
    group_name=$(getent group $GROUP_ID | cut -d: -f1) \
    && useradd -l -u $USER_ID -m -d "/home/$USER" -g "$group_name" -s /bin/sh $USER \
    && echo "$USER ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers \
    && mv /root/.cargo "/home/$USER/.cargo" \
    && mv /root/.rustup "/home/$USER/.rustup" \
    && chown -R "$USER:$group_name" "/home/$USER"

USER $USER
ENV HOME="$CTR_HOME"
ENV PATH="$HOME/.cargo/bin:$PATH"

CMD ["/bin/sh"]
