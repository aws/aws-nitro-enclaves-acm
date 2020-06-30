# Enclave image container for testing
FROM alpine:latest

# Target p11-kit-server with vsock support
# Add run-time dependencies for libvtok_rs.so
RUN apk add p11-kit-server --repository=http://dl-cdn.alpinelinux.org/alpine/edge/main && \
    apk add --no-cache libgcc && \
    apk add --no-cache gcompat && \
    apk add --no-cache --upgrade bash && \
    rm -rf /var/lib/apk

# Encryption Vault
COPY libvtok_rs.so /usr/lib/libvtok_rs.so
# Boringssl
COPY libcrypto.so /usr/lib/libcrypto.so
# Provisioning server
COPY nitro-vtoken-srv /usr/bin
# Loader
RUN  ldconfig /usr/lib/

# Init
COPY start.sh /
RUN  chmod +x /start.sh
CMD ["sh", "/start.sh"]
