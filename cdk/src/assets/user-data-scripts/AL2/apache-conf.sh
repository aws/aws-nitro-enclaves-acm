#!/bin/bash

sudo amazon-linux-extras enable aws-nitro-enclaves-cli
sudo yum -y install httpd mod_ssl
sudo yum install aws-nitro-enclaves-acm -y

# Generate the /etc/nitro_enclaves/acm.yaml file
sudo mv /etc/nitro_enclaves/acm-httpd.example.yaml /etc/nitro_enclaves/acm.yaml
sudo sed -i 's!certificate_arn: ""!certificate_arn: "CERTIFICATE_ARN_PLACEHOLDER"!' /etc/nitro_enclaves/acm.yaml

# Generate the /etc/httpd/conf.d/httpd-acm.conf file
sudo mv /etc/httpd/conf.d/ssl.conf /etc/httpd/conf.d/ssl.conf-bkp
printf "<VirtualHost *:443>\nServerName DOMAIN_NAME_PLACEHOLDER\nSSLEngine on\nSSLProtocol -all +TLSv1.2\nSSLCertificateKeyFile ""\nSSLCertificateFile ""\n</VirtualHost>\n" | sudo tee /etc/httpd/conf.d/httpd-acm.conf

# Start the ACM for Nitro Enclaves service
sudo systemctl start nitro-enclaves-acm.service
sudo systemctl enable nitro-enclaves-acm