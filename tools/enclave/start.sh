#!/bin/sh

P11_SERVER_PORT="9999"
PROVISIONING_PORT="10000"
VTOK_MODULE="/usr/lib/libvtok_rs.so"

# Start the provisioning server
nitro-vtoken-srv vsock $PROVISIONING_PORT &

# Start the p11-kit server
p11-kit server -n vsock:port=$P11_SERVER_PORT --provider $VTOK_MODULE -f -v pkcs11:
