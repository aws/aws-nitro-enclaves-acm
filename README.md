# Encryption Vault

This is a PKCS#11 provider intended to be executed within the confines of a
Nitro Enclave.

Development is aided by a Docker container that can be used to build and test
run the PKCS#11 provider as a `p11-kit` module. This container is designed to
be mostly transparent to the developer, and employed via the omnitool at
`tools/devtool`.


## Design Overview

Encryption Vault is a PKCS#11 provider (i.e. a dynamic library exposing the
PKCS#11 API). The `p11-kit` client and server are used to transport crypto
operation calls from the parent instance to the enclave, where they are handled
by Encryption Vault via the AWS libcrypto.

Here is the general flow of a parent instance crypto operation:

```
        [parent instance]                 |            [enclave]
                                          |
    OpenSSL client (e.g. nginx)           |
                |                         |
                v                         |
              OpenSSL                     |
                |                         |
                v                         |
        OpenSSL PKCS#11 Engine            |
                |                         |
                v                         |
          p11-kit client ------- vsock channel ---> p11-kit server
                                          |              |
                                          |              v
                                          |        Encryption Vault
                                          |              |
                                          |              v
                                          |	    AWS libcrypto
```

## Dependencies

All build and runtime dependencies are installed in the development container,
so the only dependency on the developer host is Docker.

If using Docker is not an option, have a look at the Dockerfile for a full list
of packages needed to build and run Encryption Vault. Additionally, the
`devtool` source (it's just a BASH script) may provide useful details on what
environment setup is required prior to building and/or running.


## Building

After cloning this repo, you need to build the development container locally:

```bash
tools/devtool mkdevctr
```

and then you can build the PKCS#11 provider:

```bash
tools/devtool build
```


## Testing in the development environment

`devtool` uses the development container to simulate both the enclave and
parent instance environments. The communication channel between `p11-kit
client` and `p11-kit server` is emulated via an Unix socket, bind-mounted into
both container environments (parent and enclave).

**Note**: The emulated enclave environment differs substantially from the
production enclave, and it is only to be used for testing the PKCS#11 API
functionality of Encryption Vault. Most notably, attestation and token
provisioning are both missing from the emulated environment.

First, the enclave container needs to be running:

```bash
tools/devtool runenclave
```

This will start `p11-kit server` with the Encryption Vault module loaded (the
module is first built if unavailable). The server is run in foreground mode, so
the Encryption Vault log will show up at `stderr`.

With the enclave environment up and running, the parent environment can be
started:

```bash
tools/devtool runparent
```

This will spin up a container with p11-kit configured to access the remote
module exposed by the enclave container via an Unix socket.
`devtool runparent` starts a BASH shell, so the user can manually test /
inspect the functionality of the Encryption Vault module; for instance, via
running `openssl` manually, directed to use the PKCS#11 engine and an URI
pointing to the Encryption Vault module:

```bash
openssl pkeyutl -keyform engine -engine pkcs11 -sign -inkey \
	"pkcs11:model=Nitro-vToken;manufacturer=Amazon;serial=EVT00;token=EncryptionVault-Token;id=%52;type=private" \
	-in hello.txt -out test.sig
```

The `tests` directory contains integration tests that can be executed to
validate the PKCS#11 module functionality using openssl or OpenSC pkcs11-tool.
Tests can be executer via:
```bash
./tests/testtool openssl
```
The above test suite is also applicable when using real enclaves.


## Testing with an enclave

The root directory of this project contains an enclave reference Dockerfile using
Alpine base for building the deliverables and then a scratch image for the run-time
image. The image spawns the provisioning server and the p11-kit server respectively
as init. This Docker image which can be used as input in the `nitro-cli` builder for
generating a bootable EIF image. See the `nitro-cli` documentation for more details.

The eVault enclave docker image can be built by executing the root builder script:
```bash
./evault-build build --tag <my-tag> --token <my-github-token>
```

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This project is licensed under the Apache-2.0 License.


