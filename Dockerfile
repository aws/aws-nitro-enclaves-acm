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
# - vtok-rand           the vToken random seeder application
# - libcrypto.so        the AWS libcrypto used by the P11 provider
# - libaws-ne-sdk-c.so  the AWS Nitro Enclaves SDK
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
    && make -j $(nproc) crypto \
    && mv third_party/boringssl/crypto/libcrypto.so /usr/lib/libcrypto.so \
    && mv third_party/boringssl/include/openssl /usr/include \
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
    make -j $(nproc) > /dev/null 2>&1 && make install

# Aws Nitro Enclaves SDK dependencies
WORKDIR /build

# AWS-S2N
ENV AWS_S2N_LIB="libs2n.a"
RUN git clone -b v0.10.11 https://github.com/awslabs/s2n.git
RUN cmake -DCMAKE_PREFIX_PATH=/usr -DCMAKE_INSTALL_PREFIX=/usr -DBUILD_SHARED_LIBS=1 -S s2n -B s2n/build
RUN cmake --build s2n/build --parallel $(nproc) --target install
# AWS-C-COMMON
ENV AWS_C_COMMON_LIB="libaws-c-common.so.0unstable"
RUN git clone -b v0.4.51 https://github.com/awslabs/aws-c-common.git
RUN cmake -DCMAKE_PREFIX_PATH=/usr -DCMAKE_INSTALL_PREFIX=/usr -DBUILD_SHARED_LIBS=1 -S aws-c-common -B aws-c-common/build
RUN cmake --build aws-c-common/build --parallel $(nproc) --target install
# AWS-C-IO
# TODO: clone the tag once PRs #302, #310 get tagged
ENV AWS_C_IO_LIB="libaws-c-io.so.0unstable"
RUN git clone -b master https://github.com/awslabs/aws-c-io.git
RUN cmake -DCMAKE_PREFIX_PATH=/usr -DCMAKE_INSTALL_PREFIX=/usr -DBUILD_SHARED_LIBS=1 -S aws-c-io -B aws-c-io/build
RUN cmake --build aws-c-io/build --parallel $(nproc) --target install
# AWS-C-COMPRESSION
ENV AWS_C_COMPRESS_LIB="libaws-c-compression.so.0unstable"
RUN git clone -b v0.2.10 http://github.com/awslabs/aws-c-compression.git
RUN cmake -DCMAKE_PREFIX_PATH=/usr -DCMAKE_INSTALL_PREFIX=/usr -DBUILD_SHARED_LIBS=1 -S aws-c-compression -B aws-c-compression/build
RUN cmake --build aws-c-compression/build --parallel $(nproc) --target install
# AWS-C-HTTP
ENV AWS_C_HTTP_LIB="libaws-c-http.so.0unstable"
RUN git clone -b v0.5.16 https://github.com/awslabs/aws-c-http.git
RUN cmake -DCMAKE_PREFIX_PATH=/usr -DCMAKE_INSTALL_PREFIX=/usr -DBUILD_SHARED_LIBS=1 -S aws-c-http -B aws-c-http/build
RUN cmake --build aws-c-http/build --parallel $(nproc) --target install
# AWS-C-CAL
ENV AWS_C_CAL_LIB="libaws-c-cal.so.0unstable"
RUN git clone -b v0.2.7 https://github.com/awslabs/aws-c-cal.git
RUN cmake -DCMAKE_PREFIX_PATH=/usr -DCMAKE_INSTALL_PREFIX=/usr -DBUILD_SHARED_LIBS=1 -S aws-c-cal -B aws-c-cal/build
RUN cmake --build aws-c-cal/build --parallel $(nproc) --target install
# AWS-C-AUTH
ENV AWS_C_AUTH_LIB="libaws-c-auth.so.0unstable"
RUN git clone -b v0.3.20 https://github.com/awslabs/aws-c-auth.git
RUN cmake -DCMAKE_PREFIX_PATH=/usr -DCMAKE_INSTALL_PREFIX=/usr -DBUILD_SHARED_LIBS=1 -S aws-c-auth -B aws-c-auth/build
RUN cmake --build aws-c-auth/build --parallel $(nproc) --target install
# JSON-C library. Has forced SOVERSION
ENV JSON_LIB="libjson-c.so.5"
RUN git clone -b json-c-0.14-20200419 https://github.com/json-c/json-c.git
RUN cmake -DCMAKE_PREFIX_PATH=/usr -DCMAKE_INSTALL_PREFIX=/usr -DBUILD_SHARED_LIBS=1 -S json-c -B json-c/build
RUN cmake --build json-c/build --parallel $(nproc) --target install
# NSM LIB
ENV NSM_LIB="libnsm.so"
RUN git clone -b master https://$USER:$TOKEN@github.com/aws/aws-nitro-enclaves-nsm-api.git && \
    cd /build/aws-nitro-enclaves-nsm-api && \
    RUSTFLAGS="-C target-feature=-crt-static" cargo build --release -j $(nproc) && \
    mv /build/aws-nitro-enclaves-nsm-api/target/release/"$NSM_LIB" /usr/lib/ && \
    mv /build/aws-nitro-enclaves-nsm-api/target/release/nsm.h /usr/include/

# AWS Nitro Enclaves SDK
ENV AWS_NE_SDK="libaws-nitro-enclaves-sdk-c.so.0unstable"
RUN git clone https://$USER:$TOKEN@github.com/aws/aws-nitro-enclaves-sdk-c

# Build the SDK against /usr/lib
RUN cp /usr/lib64/"$AWS_C_COMMON_LIB" \
    /usr/lib64/"$JSON_LIB" \
    /usr/lib64/"$AWS_C_IO_LIB" \
    /usr/lib64/"$AWS_C_CAL_LIB" \
    /usr/lib64/"$AWS_C_HTTP_LIB" \
    /usr/lib64/"$AWS_C_AUTH_LIB" \
    /usr/lib64/"$AWS_C_COMPRESS_LIB" \
    /usr/lib/

RUN cmake -DCMAKE_PREFIX_PATH=/usr -DCMAKE_INSTALL_PREFIX=/usr -DBUILD_SHARED_LIBS=1 -DBUILD_TESTING=0 \
    -S aws-nitro-enclaves-sdk-c -B aws-nitro-enclaves-sdk-c/build
RUN cmake --build aws-nitro-enclaves-sdk-c/build --target install && \
    cp /usr/lib64/"$AWS_NE_SDK" /usr/lib/

# Bring in the eVault source files
COPY . /build/sources

# Build the vToken p11 provider library and applications
WORKDIR /build/sources
RUN RUSTFLAGS="-C target-feature=-crt-static" cargo build --release -j $(nproc)

# Collect vToken random generator dependencies
ENV VTOK_RAND="vtok-rand"
RUN mkdir -p /build/output/vtok_rand
WORKDIR /build/output/vtok_rand
RUN cp /build/sources/build/target/release/"$VTOK_RAND" . && \
    ldd "$VTOK_RAND" | tr -s '[:blank:]' '\n' | grep '^/' | \
    xargs -I % sh -c 'mkdir -p $(dirname deps%); cp % deps%;'

# Collect vToken provisioning server dependencies
ENV VTOK_SRV="vtok-srv"
RUN mkdir -p /build/output/vtok_srv
WORKDIR /build/output/vtok_srv
RUN cp /build/sources/build/target/release/"$VTOK_SRV" . && \
    ldd "$VTOK_SRV" | tr -s '[:blank:]' '\n' | grep '^/' | \
    xargs -I % sh -c 'mkdir -p $(dirname deps%); cp % deps%;'

# Collect vToken library dependencies
ENV VTOK_P11="libvtok_p11.so"
RUN mkdir -p /build/output/vtok_lib
WORKDIR /build/output/vtok_lib
RUN cp /build/sources/build/target/release/"$VTOK_P11" . && \
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
    cp /build/output/p11_kit/"$P11_KIT" /rootfs/usr/bin/ && \
    mkdir -p /rootfs/usr/libexec/p11-kit/ && \
    cp /usr/libexec/p11-kit/"$P11_KIT_SRV" /rootfs/usr/libexec/p11-kit/ && \
    cp /usr/libexec/p11-kit/"$P11_KIT_REM" /rootfs/usr/libexec/p11-kit/ && \
    \
    cp /usr/lib/"$JSON_LIB" /rootfs/usr/lib/"$JSON_LIB" && \
    cp \
    /usr/lib/"$AWS_NE_SDK" \
    /usr/lib/"$AWS_C_COMMON_LIB" \
    /usr/lib/"$AWS_C_IO_LIB" \
    /usr/lib/"$AWS_C_CAL_LIB" \
    /usr/lib/"$AWS_C_HTTP_LIB" \
    /usr/lib/"$AWS_C_AUTH_LIB" \
    /usr/lib/"$AWS_C_COMPRESS_LIB" \
    /usr/lib/"$NSM_LIB" \
    /rootfs/usr/lib/

# Strip all deliverables
RUN find /rootfs/ -type f -exec strip --strip-unneeded {} \;

# Enclave initialization script. Bash is required to run it because
# we need to spawn two server programs.
RUN mkdir -p /rootfs/bin && cp /bin/sh /rootfs/bin/
RUN cp /build/sources/scripts/init/vsock/start.sh /rootfs/

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
