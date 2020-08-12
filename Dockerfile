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
# - libcrypto.so        the AWS libcrypto used by the P11 provider
#
# We use Alpine as base image for building since it has the smallest
# footprint for the required dependencies. All the applications and
# their dependencies are stored in a scratch image which shall become
# the enclave docker image for the enclave EIF.

# Latest stable (2020-05-29)
FROM alpine:3.12 as builder

# Install system dependencies / packages.
RUN apk add cmake \
    g++ \
    gcc \
    git \
    go \
    perl \
    curl \
    make \
    automake \
    autoconf \
    libtasn1-dev \
    libffi-dev \
    gettext-dev \
    libtool

# Install Rust 1.44.1
ENV PATH="/root/.cargo/bin:$PATH"
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain 1.44.1

# Build AWS libcrypto
# The user running this container shall have to provide its github user and token
ARG USER
ARG TOKEN
ENV AWS_LCRYPTO="https://$USER:$TOKEN@github.com/awslabs/aws-lc.git"

RUN mkdir -p /build
WORKDIR /build
RUN git clone -b master "$AWS_LCRYPTO" aws-lc \
    && cd aws-lc \
    && cmake -DBUILD_SHARED_LIBS=1 . \
    && make crypto \
    && mv third_party/boringssl/crypto/libcrypto.so /usr/lib/libcrypto.so \
    && ldconfig /usr/lib \
    && rm -rf /build/aws-lc

# Build p11-kit from source (0.23.20 and 0.23.19 have broken RPC compatibility)
RUN mkdir -p /build/output/p11-kit-build
WORKDIR /build/output/p11-kit-build
RUN wget https://github.com/p11-glue/p11-kit/archive/0.23.19.tar.gz
RUN tar xf 0.23.19.tar.gz && \
    cd p11-kit-0.23.19 && \
    ./autogen.sh && \
    ./configure --disable-debug --prefix=/usr \
        --sysconfdir=/etc --with-trust-paths=/etc/pki/anchors && \
    make && make install

# Build and strip the vToken deliverables
COPY . /build/vtoken
WORKDIR /build/vtoken
RUN RUSTFLAGS="-C target-feature=-crt-static" cargo build --release

# Collect vToken random generator dependencies by parsing the ldd output
ENV VTOK_RAND="vtok-rand"
RUN mkdir -p /build/output/vtok_rand
WORKDIR /build/output/vtok_rand
RUN cp /build/vtoken/build/target/release/"$VTOK_RAND" . && \
    ldd "$VTOK_RAND" | tr -s '[:blank:]' '\n' | grep '^/' | \
    xargs -I % sh -c 'mkdir -p $(dirname deps%); cp % deps%;'

# Collect vToken server dependencies by parsing the ldd output
ENV VTOK_SRV="vtok-srv"
RUN mkdir -p /build/output/vtok_srv
WORKDIR /build/output/vtok_srv
RUN cp /build/vtoken/build/target/release/"$VTOK_SRV" . && \
    ldd "$VTOK_SRV" | tr -s '[:blank:]' '\n' | grep '^/' | \
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
    mkdir -p /rootfs/usr/bin && mkdir -p /rootfs/usr/lib && \
    \
    cp -R /build/output/vtok_rand/deps/* /rootfs/ && \
    cp /build/output/vtok_rand/"$VTOK_RAND" /rootfs/usr/bin/ && \
    \
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

# Strip all deliverables
RUN find /rootfs/ -type f -exec strip --strip-unneeded {} \;

# Enclave initialization script. Bash is required to run it because
# we need to spawn two server programs.
RUN mkdir -p /rootfs/bin && cp /bin/sh /rootfs/bin/
RUN cp /build/vtoken/scripts/init/vsock/start.sh /rootfs/

# vToken run-time data and provisioning directory
# Shall be populated at run-time with vToken data
RUN mkdir -p /rootfs/vtok/device/

# Print the final rootfs (debugging helper)
RUN find /rootfs/ -type f -exec ls -lh {} \;

# Enclave image run-time. Copy the rootfs from the builder
# and execute the init script.
FROM scratch as runner

COPY --from=builder /rootfs /

CMD ["sh", "/start.sh"]
