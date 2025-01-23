# ACM for Nitro Enclaves Streamline

A CDK app that automates the installation and configuration of ACM for Nitro Enclaves on Amazon EC2 instances. This project simplifies the complex [manual installation steps](https://docs.aws.amazon.com/enclaves/latest/user/install-acm.html) by breaking them down into three modular stacks.

## Architecture Overview
The app consists of **three** main CDK stacks:

![nitro_enclaves_acm_streamline](assets/images/nitro_enclaves_acm_streamline.svg)

### 1. Certificate Stack (Step 1)
**Can be bypassed by providing an existing `certificateArn`**
1. Provisions an ACM certificate (public/private) for a specified domain
2. Handles **domain validation** requirements ([automatic if Route53 is the DNS provider, otherwise needs to be done manually](https://docs.aws.amazon.com/cdk/api/v2/docs/aws-cdk-lib.aws_certificatemanager.CertificateValidation.html#static-fromwbrdnshostedzone))

### 2. Role Stack (Steps 3, 4, 5)
- Creates and configures the ACM role
- Associates the role with the certificate
- Manages permissions for certificate and KMS key access

### 3. Instance Stack (Steps 2, 6)
- Creates an enclave-enabled EC2 instance:
    - Configures (default) VPC and security groups.
    - Supports both `NGINX` and `Apache` as server types.
    - Supports `Amazon Linux 2` and `Amazon Linux 2023` as AMI types,
- Attaches an instance profile to it based on the previously created role

## Prerequisites
- NPM
- [AWS CDK CLI](https://docs.aws.amazon.com/cdk/v2/guide/getting_started.html) installed & AWS credentials configured.
- Domain name, if creating a new certificate. Otherwise, the existing `certificateArn` (bypass certificate creation).
- For **private certificates**: Creating an AWS Private Certificate Authority (PCA)

## Installation
```bash
git clone <repository-url>
cd aws-nitro-enclaves-acm/streamline
npm install
cdk bootstrap
```

## Usage

### Examples:
#### 1. Private Certificate Deployment:
Change the configuration in the `config/default-config.ts` file.
```typescript
const config: NitroEnclavesAcmStreamlineConfig = {
  certificateConfig: {
    certificateName: 'PrivateAcmneCertificate',
    domainName: 'private.example.com',
    isPrivate: true,
    pcaArn: 'arn:aws:acm-pca:my-region-1:123456789:certificate-authority/xxx-yyyy'
  },
  roleConfig: {
    roleName: 'PrivateAcmneRole'
  },
  instanceConfig: {
    instanceName: 'PrivateAcmneInstance',
    keyPairName: 'my-private-key',
    serverType: 'NGINX',
    amiType: 'AL2',
    instanceType: 'c5.xlarge'
  },
  region: 'my-region-1',
  account: '123456789'
};
```

Deploy the stacks

```bash
cdk deploy --all --require-approval never
```
#### 2. Public Certificate Deployment (with Route53 as the DNS provider):
Change the configuration in the `config/default-config.ts` file.
```typescript
const config: NitroEnclavesAcmStreamlineConfig = {
  certificateConfig: {
    certificateName: 'PublicR53AcmneCertificate',
    domainName: 'public.example.com',
    isPrivate: false,
    hostedZoneId: 'Z123456789'
  },
  // Rest of the configuration...
};
```

Deploy the stacks

```bash
cdk deploy --all --require-approval never
```
#### 3. Public Certificate Deployment (with External DNS Provider):
For external DNS providers, deployment should be done in two steps:
- **Step 1:** Deploy certificate and **validate it (manually)**
```Typescript
// Step 1: Deploy certificate and wait for validation
const initialConfig: NitroEnclavesAcmStreamlineConfig = {
  certificateConfig: {
    certificateName: 'PublicExtDnsAcmneCertificate',
    domainName: 'public.example.com',
    isPrivate: false,
    validationType: 'DNS'  // or 'EMAIL'
  },
  // Rest of the configuration...
};
```
```bash
# Deploy the certificate stack
cdk deploy CertificateStack --require-approval never
```
- **Step 2:** Update the configuration with the generated certificate ARN
```Typescript
// After certificate validation is complete, update configuration with the certificate ARN
const finalConfig: NitroEnclavesAcmStreamlineConfig = {
  ...initialConfig,
  certificateConfig: {
    ...initialConfig.certificateConfig,
    existingCertificateArn: 'arn:aws:acm:my-region-1:123456789:certificate/xxx-yyyy' // Use the ARN of the validated certificate
  }
};
```
```bash
# Deploy remaining stacks
cdk deploy RoleStack InstanceStack --require-approval never
```

#### 4. Using an Existing Certificate:
Change the configuration in the `config/default-config.ts` file.
```typescript
const config: NitroEnclavesAcmStreamlineConfig = {
  certificateConfig: {
    certificateName: 'PublicR53AcmneCertificate',
    domainName: 'public.example.com',
    isPrivate: false,
    existingCertificateArn: 'arn:aws:acm:my-region-1:123456789:certificate/xxx-yyyy'
  },
  // Rest of the configuration...
};
```

Deploy the stacks

```bash
cdk deploy --all --require-approval never
```

### Configuration
```Typescript
    interface NitroEnclavesAcmStreamlineConfig {
    certificateConfig: {
      certificateName?: string;
      domainName: string;
      isPrivate: boolean;
      // If using a public certificate
      hostedZoneId?: string; // If Route53 is the DNS provider
      validationType?: 'DNS' | 'EMAIL'; // If using an external DNS provider
      
      // If using a private certificate
      pcaArn?: string;

      // If using an existing certificate
      existingCertificateArn?: string;
    };
    roleConfig?: {
      roleName?: string;
    };
    instanceConfig: {
      instanceName?: string;
      keyPairName: string;
      serverType: 'NGINX' | 'APACHE';
      amiType: 'AL2' | 'AL2023';
      instanceType: string;
    };
    region: string;
    account: string;
  }
```

## Deployment
The stacks can be deployed individually or together based on your needs. Required parameters vary by stack:

### Deploy all stacks:
```bash
cdk deploy --all --require-approval never
```

### Deploy individual (or multiple) stacks:
```bash
cdk deploy <stack_name_1> <stack_name_2> ... --require-approval never
```

## Cleanup
### Cleanup all stacks (and their generated resources):
```bash
cdk destroy --all
```

### Cleanup an individual stack:
```bash
cdk destroy <stack_name> 
```

## Supported Configurations

### Server Types:
* `NGINX` 
* `APACHE` - Apache HTTP Server

### AMI types:
* `AL2` - Amazon Linux 2 (AL2)
* `AL2023` - Amazon Linux 2023 (AL2023)

### Instance types:
* Only instance types that support Nitro Enclaves are supported. Ensure your selected instance type is compatible.