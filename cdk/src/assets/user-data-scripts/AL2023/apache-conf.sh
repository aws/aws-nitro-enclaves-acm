#!/bin/bash

sudo dnf install httpd mod_ssl -y
sudo dnf install aws-nitro-enclaves-acm -y

# Generate the /etc/nitro_enclaves/acm.yaml file
sudo mv /etc/nitro_enclaves/acm-httpd.example.yaml /etc/nitro_enclaves/acm.yaml
sudo sed -i 's!certificate_arn: ""!certificate_arn: "CERTIFICATE_ARN_PLACEHOLDER"!' /etc/nitro_enclaves/acm.yaml

# Generate the /etc/httpd/conf.d/httpd-acm.conf file
sudo mv /etc/httpd/conf.d/ssl.conf /etc/httpd/conf.d/ssl.conf-bkp
sudo tee /etc/httpd/conf.d/httpd-acm.conf << 'EOF'
Listen 443 https
SSLPassPhraseDialog exec:/usr/libexec/httpd-ssl-pass-dialog
SSLCryptoDevice pkcs11
<VirtualHost *:443>
ServerName DOMAIN_NAME_PLACEHOLDER
SSLEngine on
SSLProtocol -all +TLSv1.2
SSLCertificateKeyFile /etc/pki/tls/private/localhost.key
SSLCertificateFile /etc/pki/tls/certs/localhost.crt
</VirtualHost>
EOF

# Edit the OpenSSL configuration /etc/pki/tls/openssl.cnf
sudo tee -a /etc/pki/tls/openssl.cnf << 'EOF'
engines = engine_section

[engine_section]
pkcs11 = pkcs11_section

[ pkcs11_section ]
engine_id = pkcs11
init = 1
EOF

# # Start the ACM for Nitro Enclaves service
sudo systemctl start nitro-enclaves-acm.service
sudo systemctl enable nitro-enclaves-acm