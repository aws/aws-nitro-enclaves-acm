#!/bin/bash

sudo dnf install nginx -y
sudo dnf install aws-nitro-enclaves-acm -y

# Generate the /etc/nitro_enclaves/acm.yaml file
sudo mv /etc/nitro_enclaves/acm.example.yaml /etc/nitro_enclaves/acm.yaml
sudo sed -i 's!certificate_arn: ""!certificate_arn: "CERTIFICATE_ARN_PLACEHOLDER"!' /etc/nitro_enclaves/acm.yaml

# Update the /etc/nginx/nginx.conf file
sudo sed -i '/pid \/run\/nginx\.pid;/a\ssl_engine pkcs11;' /etc/nginx/nginx.conf
sudo sed -i '/# Settings for a TLS enabled server./{n;:a;/^#/s///;n;ba}' /etc/nginx/nginx.conf
sudo sed -i '/server_name/c\        server_name  DOMAIN_NAME_PLACEHOLDER;' /etc/nginx/nginx.conf
sudo sed -i '/ssl_certificate/d; /ssl_certificate_key/d; /ssl_ciphers/d' /etc/nginx/nginx.conf
sudo sed -i '/ssl_session_timeout/a\        ssl_protocols TLSv1.2;' /etc/nginx/nginx.conf
sudo sed -i '/# Load configuration files for the default server block./a\        include "/etc/pki/nginx/nginx-acm.conf";' /etc/nginx/nginx.conf

# Edit the OpenSSL configuration /etc/pki/tls/openssl.cnf
sudo sed -i '/ssl_conf = ssl_module/a\engines = engine_section\n\n[engine_section]\npkcs11 = pkcs11_section\n\n[ pkcs11_section ]\nengine_id = pkcs11\ninit = 1' /etc/pki/tls/openssl.cnf

# Start the ACM for Nitro Enclaves service
sudo systemctl start nitro-enclaves-acm.service
sudo systemctl enable nitro-enclaves-acm