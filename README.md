# AWS Certificate Manager for Nitro Enclaves

This is a PKCS#11 provider intended to be executed within the confines of a
Nitro Enclave.

Development is aided by Docker containers that can be used to build and test
run the PKCS#11 provider as a `p11-kit` module. These containers are designed to
be mostly transparent to the developer, and employed via the omnitool at
`tools/devtool`.

## How to install and setup

The user guide for the ACM for Nitro Enclaves can be found at https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-refapp.html.

# Managed tokens

Each token can store an end-entity private key and its associated ACM certificate chain. Up to 128 SSL/TLS X.509 ACM certificates can be managed via provisioned tokens by the nitro-enclaves-acm service.
Configuration options can be found in the `/etc/nitro_enclaves/acm.yaml` post service installation.

## Design Overview

ACM for Nitro Enclaves is a PKCS#11 provider (i.e. a dynamic library exposing the
PKCS#11 API). The `p11-kit` client and server are used to transport crypto
operation calls from the parent instance to the enclave, where they are handled
by this provider via the AWS cryptographic library.

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
                                          |    ACM for Nitro Enclaves module
                                          |              |
                                          |              v
                                          |	        AWS libcrypto
```

## Dependencies

| name                       | version              | link                                              |
|----------------------------|----------------------|---------------------------------------------------|
| aws-lc                     | v0.0.2               | https://github.com/awslabs/aws-lc/                |
| aws-nitro-enclaves-sdk     | v0.2.0               | https://github.com/aws/aws-nitro-enclaves-sdk-c   |
| s2n-tls                    | v1.1.1               | https://github.com/aws/s2n-tls.git                |
| aws-c-common               | v0.6.1               | https://github.com/awslabs/aws-c-common           |
| aws-c-io                   | v0.10.9              | https://github.com/awslabs/aws-c-io               |
| aws-c-compression          | v0.2.14              | https://github.com/awslabs/aws-c-compression      |
| aws-c-http                 | v0.6.7               | https://github.com/awslabs/aws-c-http             |
| aws-c-cal                  | v0.5.12              | https://github.com/awslabs/aws-c-cal              |
| aws-c-auth                 | v0.6.4               | https://github.com/awslabs/aws-c-auth             |
| aws-nitro-enclaves-nsm-api | v0.1.0               | https://github.com/aws/aws-nitro-enclaves-nsm-api |
| json-c                     | json-c-0.15-20200726 | https://github.com/json-c/json-c                  |

`devtool` sets up two containers: one for emulating the enclave environment,
and another for emulating the parent instance environment.

If using Docker is not an option, have a look at the Dockerfile for a full list
of packages needed to build and run the ACM for Nitro Enclaves module. Additionally,
the `devtool` source (it's just a BASH script) may provide useful details on what
environment setup is required prior to building and/or running.

## Components

ACM for Nitro Enclaves has a few different components, some meant to be run inside the enclave,
others inside the parent instance:
- enclave-side components:
  - `p11ne-srv` - the AWS for NE RPC server, used to query the state of the pkcs#11 enclave
                  device, and to provision its database;
  - `libvtok_p11.so` - the PKCS#11 provider implementation;
- parent-instance-side components:
  - `p11ne-client` - the ACM for NE RPC client, providing a low-level interface to
                     the ACM for NE RPC server;
  - `p11ne-cli` - a user-facing CLI tool that can be used to manage the
                  ACM for NE enclave (e.g. provision a PKCS#11 token);
  - `p11ne-db`- a user-facing CLI tool that can be used to pack a private key and
                its associated certificate (or certificate chain) in a database format
				for provisioning a PKCS#11 token

## Building

Use `devtool` to build any ACM for NE component, by invoking `devtool build <component>`.

E.g. building the PKCS#11 provider:

```bash
tools/devtool build libvtok_p11.so
```

Building the (development version of) ACM for NE enclave image (EIF):

```bash
tools/devtool build dev-image
```

See `devtool help` for more build options.

## Testing in the development environment

`devtool` uses development containers to simulate both the enclave and
parent instance environments. The communication channel between `p11-kit
client` and `p11-kit server` is emulated via a Unix socket, bind-mounted into
both container environments (parent and enclave).

**Note**: The emulated enclave environment differs substantially from the
production enclave, and it is only to be used for testing the PKCS#11 API
functionality of the ACM for Nitro Enclaves module. Most notably, attestation and token
provisioning are both missing from the emulated environment.

First, the enclave container needs to be running:

```bash
tools/devtool simulate-enclave
```

This will start `p11-kit server` with the ACM for Nitro Enclaves module loaded (the
module is first built if unavailable). The server is run in foreground mode, so
the pkcs#11 provider module log will show up at `stderr`.

With the enclave environment up and running, the parent environment can be
started:

```bash
tools/devtool simulate-parent
```

This will spin up a container with p11-kit configured to access the remote
module exposed by the enclave container via a Unix socket.
`devtool simulate-parent` starts a BASH shell, so the user can manually test /
inspect the functionality of the ACM for Nitro Enclaves module; for instance, via
running `openssl` manually, directed to use the PKCS#11 engine and a URI
pointing to the pkcs#11 provider module token:

```bash
openssl pkeyutl -keyform engine -engine pkcs11 -sign -inkey \
	"pkcs11:model=p11ne-token;manufacturer=Amazon;serial=EVT00;token=my-token-label;id=%52;type=private" \
	-in hello.txt -out test.sig
```

The `tests` directory contains integration tests that can be executed to
validate the PKCS#11 module functionality using openssl or OpenSC pkcs11-tool.

Build the testhelper binary:
```bash
$ cd tests/helpers && cargo build --release

$ cd - && cp build/target/release/testhelpers ./tests
```
After this, the test suite can be executed via the command:
```bash
$ ./tests/testtool openssl --kms-key-id <your-kms-key-id> --kms-region <your-kms-key-region>

```
The above cryptographic test suite is applicable when using real enclaves on EC2 instances
where an instance role and a KMS key has already been setup accordingly for provisioning the
test pkcs#11 token with the private keys.

## License

This project is licensed under the Apache-2.0 License.

## Security issue notifications

If you discover a potential security issue in ACM for Nitro Enclaves, we ask that you notify AWS
Security via our
[vulnerability reporting page](https://aws.amazon.com/security/vulnerability-reporting/).
Please do **not** create a public GitHub issue.
