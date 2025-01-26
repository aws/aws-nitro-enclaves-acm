#!/bin/bash

sudo dnf install httpd mod_ssl -y
sudo dnf install aws-nitro-enclaves-acm -y

# Generate the /etc/nitro_enclaves/acm.yaml file
sudo mv /etc/nitro_enclaves/acm-httpd.example.yaml /etc/nitro_enclaves/acm.yaml
sudo sed -i 's!certificate_arn: ""!certificate_arn: "CERTIFICATE_ARN_PLACEHOLDER"!' /etc/nitro_enclaves/acm.yaml

# Generate the /etc/httpd/conf.d/httpd-acm.conf file
sudo mv /etc/httpd/conf.d/ssl.conf /etc/httpd/conf.d/ssl.conf-bkp
printf "Listen 443 https\nSSLPassPhraseDialog exec:/usr/libexec/httpd-ssl-pass-dialog\nSSLCryptoDevice pkcs11\n<VirtualHost *:443>\nServerName DOMAIN_NAME_PLACEHOLDER\nSSLEngine on\nSSLProtocol -all +TLSv1.2\nSSLCertificateKeyFile /etc/pki/tls/private/localhost.key\nSSLCertificateFile /etc/pki/tls/certs/localhost.crt\n</VirtualHost>\n" | sudo tee /etc/httpd/conf.d/httpd-acm.conf

# Edit the OpenSSL configuration /etc/pki/tls/openssl.cnf
sudo sed -i '/ssl_conf = ssl_module/a\engines = engine_section\n\n[engine_section]\npkcs11 = pkcs11_section\n\n[ pkcs11_section ]\nengine_id = pkcs11\ninit = 1' /etc/pki/tls/openssl.cnf

# # Start the ACM for Nitro Enclaves service
sudo systemctl start nitro-enclaves-acm.service
sudo systemctl enable nitro-enclaves-acm