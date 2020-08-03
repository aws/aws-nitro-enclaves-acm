# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# vToken enclave image Dockerfile
#
# Constructs a minimal image for running the Nitro vToken enclave.
# The applications of interest can only work dynamically thus
# they require to have all their runtime dependencies in the enclave
# userspace. The vToken enclave has the following main deliverables:
#
# - p11-kit-server      the P11 server
# - libvtok_p11.so      the P11 provider
# - vtok-srv            the vToken provisioning server
#
# We use Alpine as base image for building since it has the smallest
# footprint for the required dependencies. All the applications and
# their dependencies are stored in a scratch image which shall become
# the enclave docker image for the enclave EIF.

# Latest stable (2020-05-29)
FROM alpine:3.12 as builder

# Install system dependencies / packages.
RUN apk add p11-kit-server \
        cmake \
        g++ \
        gcc \
        git \
        go \
        perl \
        curl \
        make

# Install Rust from stable
ENV PATH="/root/.cargo/bin:$PATH"
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain stable

# Build boringssl libcrypto
ENV BORINGSSL_GIT="https://github.com/google/boringssl.git"
RUN mkdir -p /build \
    && cd /build \
    && git clone -b chromium-stable "$BORINGSSL_GIT" boringssl \
    && cd boringssl \
    && cmake -DBUILD_SHARED_LIBS=1 . \
    && make crypto \
    && mv crypto/libcrypto.so /usr/lib/libcrypto.so \
    && ldconfig /usr/lib \
    && rm -rf /build/boringssl

# Build and strip the vToken deliverables
COPY . /build/vtoken
WORKDIR /build/vtoken
RUN RUSTFLAGS="-C target-feature=-crt-static" cargo build --release && \
    strip --strip-all \
    build/target/release/vtok-srv \
    build/target/release/libvtok_p11.so
    
# Collect the vToken server dependencies by parsing the ldd output
ENV VTOK_SRV="vtok-srv"
RUN mkdir -p /build/output/vtok_srv
WORKDIR /build/output/vtok_srv
RUN cp /build/vtoken/build/target/release/"$VTOK_SRV" . && \
    ldd "$VTOK_SRV" -srv | tr -s '[:blank:]' '\n' | grep '^/' | \
    xargs -I % sh -c 'mkdir -p $(dirname deps%); cp % deps%;'
# Collect vToken library dependencies by parsing the ldd output
ENV VTOK_P11="libvtok_p11.so"
RUN mkdir -p /build/output/vtok_lib
WORKDIR /build/output/vtok_lib
RUN cp /build/vtoken/build/target/release/"$VTOK_P11" . && \
    ldd "$VTOK_P11" | tr -s '[:blank:]' '\n' | grep '^/' | \
    xargs -I % sh -c 'mkdir -p $(dirname deps%); cp % deps%;'
# Collect p11-kit-server dependencies by parsing the ldd output
ENV P11_KIT="p11-kit"
ENV P11_KIT_SRV="p11-kit-server"
ENV P11_KIT_REM="p11-kit-remote"
RUN mkdir /build/output/p11_kit
WORKDIR /build/output/p11_kit
RUN cp /usr/bin/"$P11_KIT" . && \
    ldd "$P11_KIT" | tr -s '[:blank:]' '\n' | grep '^/' | \
    xargs -I % sh -c 'mkdir -p $(dirname deps%); cp % deps%;' && \
    ldd /usr/libexec/p11-kit/"$P11_KIT_SRV" | tr -s '[:blank:]' '\n' | grep '^/' | \
    xargs -I % sh -c 'mkdir -p $(dirname deps%); cp % deps%;' && \
    ldd /usr/libexec/p11-kit/"$P11_KIT_REM" | tr -s '[:blank:]' '\n' | grep '^/' | \
    xargs -I % sh -c 'mkdir -p $(dirname deps%); cp % deps%;'

# Create the enclave rootfs. Add the applications and store
# the reunion of all their dependencies (since most of them are common).
RUN mkdir /rootfs && \
    \
    mkdir -p /rootfs/usr/bin && mkdir -p /snaphot/usr/lib && \
    cp -R /build/output/vtok_srv/deps/* /rootfs/ && \
    cp /build/output/vtok_srv/"$VTOK_SRV" /rootfs/usr/bin/ && \
    \
    cp -R /build/output/vtok_lib/deps/* /rootfs/ && \
    cp /build/output/vtok_lib/"$VTOK_P11" /rootfs/usr/lib/ && \
    \
    cp -R /build/output/p11_kit/deps/* /rootfs/ && \
    cp /build/output/p11_kit/"$P11_KIT" /rootfs/usr/bin && \
    mkdir -p /rootfs/usr/libexec/p11-kit/ && \
    cp /usr/libexec/p11-kit/"$P11_KIT_SRV" /rootfs/usr/libexec/p11-kit/ && \
    cp /usr/libexec/p11-kit/"$P11_KIT_REM" /rootfs/usr/libexec/p11-kit/

# Enclave initialization script. Bash is required to run it because
# we need to spawn two server programs.
RUN mkdir -p /rootfs/bin && cp /bin/sh /rootfs/bin/
COPY ./tools/enclave/start.sh /rootfs/

# vToken run-time data and provisioning directory
# Shall be populated at run-time with vToken data and provisioning blobs.
RUN mkdir -p /rootfs/vtok

# Print the rootfs (debugging helper)
RUN find /rootfs/ -type f -exec ls -lh {} \;

# Enclave image run-time. Copy the rootfs from the builder
# and execute the init script.
FROM scratch as runner

COPY --from=builder /rootfs /

CMD ["sh", "/start.sh"]
