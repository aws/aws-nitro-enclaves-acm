# Java PKCS11 Keystore

A Java keystore is a repository where public certificates alongside their corresponding private keys are stored.
In the context of SSL/TLS, the server private key and its associated certificate chain can
be imported in the keystore by using the PKCS11 storetype via the configured PKCS#11 provider.
Details can be found in the [Java PKCS#11 Reference Guide](https://docs.oracle.com/en/java/javase/17/security/pkcs11-reference-guide1.html#GUID-30E98B63-4910-40A1-A6DD-663EAF466991)
which uses the SunPKCS11 provider on an AWS EC2 instance.

In this implementation, the PKCS#11 provider is intended to be executed within the confines of a Nitro Enclave.

> NOTE: In the current implementation, only the SunPKCS11 provider keystore Read-Only requirements are supported. See [here](https://docs.oracle.com/en/java/javase/17/security/pkcs11-reference-guide1.html#GUID-F068390B-EB41-48A0-A713-B4CBCC72285D). This is because the enclave pkcs#11 token is write-protected and
> does not allow creating, modifying or destroying cryptographic objects after provisioning.

1. Install a Java Development Kit of your choice. For example, [Amazon Corretto](https://docs.aws.amazon.com/corretto/).

2. Create the SunPKCS11 provider configuration file in your location of choice
```sh
cat /etc/pkcs11/keystore.conf

name = p11ne
description = "PKCS#11 Keystore"
library = /usr/lib64/libp11-kit.so.0
```

3. Add the SunPKCS11 provider configuration file in the security provider list
```sh
cat /usr/lib/jvm/java-17-amazon-corretto/conf/security/java.security | grep security.provider
...
security.provider.10=JdkLDAP
security.provider.11=JdkSASL
security.provider.12=SunPKCS11 /etc/pkcs11/keystore.conf
```

4. Setup ACM for Nitro Enclaves as per the [documentation](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-refapp.html).
After successfully starting the `nitro-enclaves-acm.service`, the enclave shall be up and running with a pkcs#11 token
provisioned with a private key and the ACM certificate chain.

5. The keystore should now be able to access the entries within the token. In this example, it finds a private key
and its associated certificate chain.
```sh
$ keytool -storetype PKCS11 -providerName SunPKCS11-p11ne -keystore NONE -storepass <token-pin> -list
Keystore type: PKCS11
Keystore provider: SunPKCS11-p11ne

Your keystore contains 2 entries

acm-ne-cert-0, PrivateKeyEntry,
Certificate fingerprint (SHA-256): 5A:4C:7F:85:07:DA:BA:80:7E:2C:FB:28:F3:BC:26:D2:5F:75:C8:FE:01:2E:E3:BB:47:31:A7:71:0D:85:58:D9
acm-ne-cert-1, trustedCertEntry,
Certificate fingerprint (SHA-256): 50:B0:90:E5:BD:54:A0:73:4C:88:87:A8:6B:6B:AF:EC:67:D7:96:5F:71:C3:9B:C6:3F:1C:17:17:AF:38:EE:0B
```

> NOTE: For development or various testing the [p11ne-db](https://github.com/aws/aws-nitro-enclaves-acm/blob/main/tools/p11ne-db) tool can be used to encrypt a plain private key using
> a KMS key and pack it with its associated certificate chain. The [p11ne-cli](https://github.com/aws/aws-nitro-enclaves-acm/blob/main/tools/p11ne-cli) tool can be used to start and provision an pkcs#11 enclave token.
```sh
p11ne-db pack-key --id 1 --label test-key --cert-file server.crt --key-file server.key --out-file keystore --kms-key-id <your-kms-key-id> --kms-region <your-kms-key-region>
p11ne-cli start
p11ne-cli init-token --key-db keystore.db --label test-token --pin <token-pin>
```
