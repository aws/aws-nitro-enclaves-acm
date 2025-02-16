#!/bin/bash

sudo amazon-linux-extras enable aws-nitro-enclaves-cli
sudo yum -y install httpd mod_ssl
sudo yum install aws-nitro-enclaves-acm -y

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

# Start the ACM for Nitro Enclaves service
sudo systemctl start nitro-enclaves-acm.service
sudo systemctl enable nitro-enclaves-acm