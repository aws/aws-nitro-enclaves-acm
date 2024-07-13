# How to use the s3-db tool?

The s3-db tool is a utility to create key material databases and store them on an S3 bucket. Essentially, it enables users to utilize their certificates/keys for testing purposes.
Before using the tool, the key materials must be created in advance. By using the following commands, a self-signed certificate, certificate chain, and a private key can be generated:

Generate a private key:
```
openssl genrsa -out private.key 2048
```

Create a Certificate Signing Request (CSR):
```
openssl req -new -key private.key -out csr.csr
```

Generate a self-signed certificate:
```
openssl x509 -req -days 365 -in csr.csr -signkey private.key -out certificate.crt
```

Create a Certificate Authority (CA) certificate:
```
openssl req -x509 -newkey rsa:4096 -nodes -keyout ca.key -out ca.crt -days 365
```

Sign the certificate with the CA:
```
openssl x509 -req -in csr.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out certificate.crt -days 365 -sha256
```

Finally, create a certificate chain (concatenate the server certificate and CA certificate):
```
cat certificate.crt ca.crt > certificate_chain.crt
```

Once we have the key materials prepared, we can create a database by invoking the s3-db utility with the create command:

```
s3-db create --kms-key-id <your-kms-key-id> \
             --kms-region <your-kms-region> \
             --certificate-path <your-certificate> \
             --certificate-chain-path <your-certificate-chain> \
             --private-key-path <your-private-key> \
             --output-path <your-db-path>
```

With the database created, we can use the push command to upload it to the S3 URI specified in the configuration file (/etc/nitro_enclaves/acm.yaml).
The command below copies your local database file to the designated S3 bucket.

```
s3-db push --s3-region <your-s3-region> --input-path <your-db-path> --s3-uri s3://<your-s3-uri-in-the-yaml-file>
```

Now, you are ready to use your key material database for testing. Finally, the following policy must be attached to the IAM role associated with the instance:

```
{
    "Effect": "Allow",
    "Action": [
        "s3:GetObject",
        "s3:ListAccessGrants"
    ],
    "Resource": [
        "arn:aws:s3:::<your-s3-bucket-name>",
        "arn:aws:s3:::<your-s3-bucket-name>/<path-to-your-object>"
    ]
}
```
