# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

ARG BASE_IMG
FROM $BASE_IMG as builder

ARG EVBIN_RPC_SERVER
ARG EVBIN_P11_MOD
ARG EVBIN_INIT

USER root

COPY $EVBIN_RPC_SERVER /usr/bin/
COPY $EVBIN_P11_MOD /usr/lib/
COPY $EVBIN_INIT /usr/bin/

RUN mkdir -p /rootfs/p11ne
WORKDIR /rootfs

# Collect eVault lib deps
RUN BINS="\
    /usr/bin/$EVBIN_RPC_SERVER \
    /usr/bin/$EVBIN_INIT \
    /usr/lib/$EVBIN_P11_MOD \
    /usr/bin/p11-kit \
    /usr/libexec/p11-kit/p11-kit-server \
    /usr/libexec/p11-kit/p11-kit-remote \
    " && \
    for bin in $BINS; do \
        { echo "$bin"; ldd "$bin" | grep -Eo "/.*lib.*/[^ ]+"; } | \
            while read path; do \
                mkdir -p ".$(dirname $path)"; \
                cp -fL "$path" ".$path"; \
                strip --strip-unneeded ".$path"; \
            done \
    done
RUN mkdir -p /rootfs/etc/ssl/certs \
    && cp -f /etc/ssl/certs/ca-certificates.crt /rootfs/etc/ssl/certs/
RUN mkdir -p /rootfs/p11ne

RUN mkdir -p /rootfs/bin/ && \
    cp /rootfs/usr/bin/"$EVBIN_INIT" /rootfs/bin/init && \
    chmod +x /rootfs/bin/init

RUN find /rootfs

FROM scratch
COPY --from=builder /rootfs /
WORKDIR /run/p11ne
CMD ["/bin/init"]
