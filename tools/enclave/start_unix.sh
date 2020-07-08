#!/bin/sh

# Development enclave container init script over AF_UNIX transport

CTR_SRC_DIR="/vtok"
CTR_BUILD_DIR="$CTR_SRC_DIR/build"
CTR_TARGET_DIR="$CTR_BUILD_DIR/target/debug"
CTR_P11_SOCK_PATH="$CTR_BUILD_DIR/p11.sock"
CTR_PRV_SOCK_PATH="$CTR_BUILD_DIR/rpc.sock"
CTR_VTOK_MODULE="$CTR_TARGET_DIR/libvtok_p11.so"
CTR_PROVISIONING_SERVER="$CTR_TARGET_DIR/vtok-srv"

# Remove the file (if it exists)
rm $CTR_PRV_SOCK_PATH

# Start the provisioning server
$CTR_PROVISIONING_SERVER unix $CTR_PRV_SOCK_PATH &

# Start the p11-kit server
p11-kit server -n "unix:path=$CTR_P11_SOCK_PATH" \
        --provider $CTR_VTOK_MODULE -f -v pkcs11:
