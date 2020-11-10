#!/bin/bash
# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

USAGE="
    p11ne installer for Amazon Linux 2 - install and set up p11ne and its dependencies

    Usage: $0 --target <devctr|release>

    This scripts expects:
    - an Amazon Linux 2 environment, preferably a clean base AMI;
    - <script dir>/install [optional]           A rootfs structure, holding any pre-built
                                                binaries that should be installed.

    Options:
        --target <devctr|release>               The build target:
                                                - devctr: set up the dev container;
                                                - release: set up the release parent AMI;
"

NITRO_ENCLAVES_GROUP=ne
THIS_DIR="$(cd "$(dirname "$0")" && pwd)"
OPT_TARGET=

BUILD_DEPS=(
    autoconf
    automake
    cmake
    gcc
    gettext-devel
    git
    libffi-devel
    libtool
    make
    openssl-devel
)

say_err() {
    echo "$*" 1>&2
}

die() {
    [[ $# -gt 0 ]] && say_err "$*"
    exit 1
}

ok_or_die() {
    [ $? -eq 0 ] || die "$*"
}

p11ne_is_release_setup() {
    [[ $OPT_TARGET = release ]]
}

p11ne_setup_parent() {
    # Install build deps that are currently missing. We will be removing these before
    # the end, so we need to avoid removing any packages that we need, but were already
    # installed.
    MY_BUILD_DEPS=($(for dep in "${BUILD_DEPS[@]}"; do rpm -q $dep > /dev/null || echo $dep; done))
    yum install -y "${MY_BUILD_DEPS[@]}" \
        && yum install -y gnutls-utils jq tar p11-kit
    ok_or_die

    amazon-linux-extras install -y docker aws-nitro-enclaves-cli nginx1 \
        && yum install -y aws-nitro-enclaves-cli-devel
    ok_or_die

    cd "$THIS_DIR"

    if [[ -d install ]]; then
        pushd install \
            && tar -c . | tar -xC / \
            && popd
        ok_or_die "Pre-built rootfs install failed."
    fi

    if p11ne_is_release_setup; then
        systemctl enable docker
        systemctl enable nitro-enclaves-allocator
        ok_or_die "Error setting up startup services"

        # Make sure ec2-user has access to nitro-cli resources
        usermod -aG $NITRO_ENCLAVES_GROUP ec2-user \
            && usermod -aG docker ec2-user
        ok_or_die "Unable to grant Nitro Enclaves access to ec2-user."
    fi

    mkdir -p "$THIS_DIR/src" && cd "$THIS_DIR/src"

    # TODO: update to a newer, untagged commit, if we need the pin-source feature.
    # Install libp11 (openssl PKCS#11 engine) from sources
    git clone https://github.com/OpenSC/libp11.git \
        && pushd libp11 \
        && git reset --hard libp11-0.4.10 \
        && ./bootstrap \
        && ./configure --prefix=/usr --with-pkcs11-module=/usr/lib64/p11-kit-proxy.so \
        && make -j $(nproc) \
        && make install
    ok_or_die
    popd

    # Clean up
    if p11ne_is_release_setup; then
        # Remove build-time deps
        yum remove -y "${MY_BUILD_DEPS[@]}"
        yum autoremove -y
    fi
}

main() {
    while [[ -n "$1" ]]; do
        case "$1" in
            --target)
                [[ -n "$2" ]] || die "Error: missing target. See --help."
                [[ "$2" = devctr ]] || [[ "$2" = release ]] || die "Invalid target: $2".
                OPT_TARGET="$2"
                shift
                ;;
            --help|-h|help)
                die "$USAGE"
                ;;
        esac
        shift
    done

    [[ -n "$OPT_TARGET" ]] || die "Error: missing target. See --help."

    p11ne_setup_parent
}

main "$@"
