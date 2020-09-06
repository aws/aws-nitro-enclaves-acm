# Encryption Vault

This is a PKCS#11 provider intended to be executed within the confines of a
Nitro Enclave.

Development is aided by Docker containers that can be used to build and test
run the PKCS#11 provider as a `p11-kit` module. These containers are designed to
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
                                          |	        AWS libcrypto
```

## Dependencies

`devtool` sets up two containers: one for emulating the enclave environment,
and another for emulating the parent instance environment.

Most dependencies are handled by the containers. However, there are still a few
required on the host development machine: docker, bash, git, and make.

## Components

eVault has a few different components, some meant to be run inside the enclave,
others inside the parent instance:
- enclave-side components:
  - `vtok-rand` - entropy seeder, run once at enclave boot;
  - `vtok-srv` - the eVault RPC server, used to query the state of the eVault
     device, and to provision its database;
  - `libvtok_p11.so` - the PKCS#11 provider;
- parent-instance-side components:
  - `nitro-vtoken` - the eVault RPC client, providing a low-level interface to
    the eVault RPC server;
  - `nitro-evault` - a user-facing CLI tool that can be used to manage the
    eVault enclave (e.g. provision PKCS#11 tokens)

## Building

Use `devtool` to build any eVault component, by invoking `devtool build <component>`.

E.g. building the PKCS#11 provider:

```bash
tools/devtool build libvtok_p11.so
```

Building the (development version of) eVault enclave image (EIF):

```bash
tools/devtool build dev-image
```

See `devtool help` for more build options.

## Testing in the development environment

`devtool` uses development containers to simulate both the enclave and
parent instance environments. The communication channel between `p11-kit
client` and `p11-kit server` is emulated via an Unix socket, bind-mounted into
both container environments (parent and enclave).

**Note**: The emulated enclave environment differs substantially from the
production enclave, and it is only to be used for testing the PKCS#11 API
functionality of Encryption Vault. Most notably, attestation is missing from
the emulated environment.

First, the enclave container needs to be running:

```bash
tools/devtool simulate-enclave
```

This will start `p11-kit server` with the Encryption Vault module loaded (the
module is first built if unavailable). The server is run in foreground mode, so
the Encryption Vault log will show up at `stderr`.

With the enclave environment up and running, the parent environment can be
started:

```bash
tools/devtool simulate-parent
```

This will spin up a container with p11-kit configured to access the remote
module exposed by the enclave container via an Unix socket.
`devtool runparent` starts a BASH shell, so the user can manually test /
inspect the functionality of the Encryption Vault module; for instance, via
running `openssl` manually, directed to use the PKCS#11 engine and an URI
pointing to the Encryption Vault module:

```bash
openssl pkeyutl -keyform engine -engine pkcs11 -sign -inkey \
	"pkcs11:model=evault-token;manufacturer=Amazon;serial=EVT00;token=my-token-label;id=%52;type=private" \
	-in hello.txt -out test.sig
```

The `tests` directory contains integration tests that can be executed to
validate the PKCS#11 module functionality using openssl or OpenSC pkcs11-tool.
Tests can be executer via:
```bash
./tests/testtool openssl
```
The above test suite is also applicable when using real enclaves.

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This project is licensed under the Apache-2.0 License.

