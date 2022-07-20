# Apache HTTPD managed service

1. Install Apache httpd with SSL/TLS support
```sh
sudo yum install -y httpd mod_ssl
```

2. Setup your SSL/TLS configuration as per the [documentation](https://httpd.apache.org/docs/2.4/ssl/ssl_howto.html).
Post-installation the `mod_ssl` package presents the `ssl.conf` file below. Configure it with your custom directives
and optionally rename it:

```sh
sudo mv /etc/httpd/conf.d/ssl.conf /etc/httpd/conf.d/httpd-acm.conf
```

> NOTE: A minimal TLS/SSL configuration example (as per [documentation)](https://httpd.apache.org/docs/2.4/ssl/ssl_howto.html):
```sh
<VirtualHost *:443>
ServerName www.acm-httpd.example
SSLEngine on
SSLProtocol -all +TLSv1.2

SSLCertificateKeyFile ""
SSLCertificateFile ""
</VirtualHost>
```

> NOTE: The `SSLCertificateFile` and `SSLCertificateKeyFile` entries must be present in the configuration enabled and
at the beginning of the configuration line (as per default `mod_ssl` ssl.conf file). The `nitro-enclaves-acm.service`
shall scan the configuration file and update them with the correct pkcs#11 URIs after the token gets provisioned with the
ACM certificate key.

3. Setup ACM for Nitro Enclaves as per the [documentation](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-refapp.html).

> NOTE: Copy the default ACM for Nitro Enclaves httpd service configuration file example:
```sh
sudo mv /etc/nitro_enclaves/acm-httpd.example.yaml /etc/nitro_enclaves/acm.yaml
```

4. Make sure that the `/etc/nitro_enclaves/acm.yaml` file contains the `Conf` directive `path` entry to point at your
httpd SSL/TLS configuration file from step `2` above.
After successfully starting the `nitro-enclaves-acm.service`, the enclave shall be up and running with a pkcs#11 token
provisioned with a private key and the ACM certificate chain.

5. Test that the server works as expected
```sh
curl --cacert path_to_pem_file --tlsv1.2 https://host_name_or_IP
```
or
```sh
curl -k --tlsv1.2 https://host_name_or_IP
```

> NOTE: If you used a private certificate, you must add the host name to `/etc/hosts` in the following format: `127.0.0.1 host_name`.
