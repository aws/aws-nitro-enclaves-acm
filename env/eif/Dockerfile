# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

ARG BASE_IMG
FROM $BASE_IMG as builder

ARG EVBIN_RPC_SERVER
ARG EVBIN_RAND
ARG EVBIN_P11_MOD

USER root

COPY $EVBIN_RPC_SERVER /usr/bin/
COPY $EVBIN_RAND /usr/bin/
COPY $EVBIN_P11_MOD /usr/lib/

RUN mkdir -p /rootfs/evault
WORKDIR /rootfs

# Collect eVault lib deps
RUN BINS="\
    /bin/sh \
    /usr/bin/$EVBIN_RPC_SERVER \
    /usr/bin/$EVBIN_RAND \
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
RUN mkdir -p /rootfs/evault

RUN echo -e "#!/bin/sh\n\
cd /evault\n\
$EVBIN_RAND\n\
$EVBIN_RPC_SERVER vsock 10000 &\n\
p11-kit server -n vsock:port=9999 --provider /usr/lib/$EVBIN_P11_MOD -f -v pkcs11:\n\
" > /rootfs/bin/init \
    && chmod +x /rootfs/bin/init

RUN find /rootfs

FROM scratch
COPY --from=builder /rootfs /
WORKDIR /run/evault
CMD ["/bin/init"]
