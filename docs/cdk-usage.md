# CDK Usage Guide - ACM for Nitro Enclaves Streamline

This guide covers advanced deployment scenarios using [CDK CLI](https://docs.aws.amazon.com/cdk/v2/guide/cli.html) directly and detailed configuration options.

## Configuration Interface
```typescript
interface NitroEnclavesAcmStreamlineConfig {
  certificateConfig: {
    stackName: string,
    certificateName?: string;
    domainName: string;
    isPrivate: boolean;
    hostedZoneId?: string;
    validationType?: 'DNS' | 'EMAIL';
    pcaArn?: string;
    existingCertificateArn?: string;
  };
  roleConfig?: {
    stackName: string,
    roleName?: string;
  };
  instanceConfig: {
    stackName: string,
    instanceName?: string;
    keyPairName: string;
    serverType: 'NGINX' | 'APACHE';
    amiType: 'AL2' | 'AL2023';
    instanceType: string;
    encryptVolume: boolean,
    allowSSHPort: boolean,
  };
  region: string;
  account: string;
}
```
The default configuration file can be found in [`src/config/default-config.ts`](../src/config/default-config.ts)

## CDK Deployment Examples:
### 1. Private Certificate Deployment:
Change the configuration in the [`src/config/default-config.ts`](../src/config/default-config.ts) file.
```typescript
const config: NitroEnclavesAcmStreamlineConfig = {
  certificateConfig: {
    stackName: 'CertificateStack',
    certificateName: 'PrivateAcmneCertificate',
    domainName: 'private.example.com',
    isPrivate: true,
    pcaArn: 'arn:aws:acm-pca:my-region-1:123456789:certificate-authority/xxx-yyyy'
  },
  roleConfig: {
    stackName: 'RoleStack',
    roleName: 'PrivateAcmneRole'
  },
  instanceConfig: {
    stackName: 'InstanceStack',
    instanceName: 'PrivateAcmneInstance',
    keyPairName: 'my-private-key',
    serverType: 'NGINX',
    amiType: 'AL2',
    instanceType: 'c5.xlarge'
    encryptVolume: false,
    allowSSHPort: false,
  },
  region: 'my-region-1',
  account: '123456789'
};
```

Deploy the stacks

```bash
cdk deploy --all
```
### 2. Public Certificate Deployment (with Route53 as the DNS provider):
Change the configuration in the [`src/config/default-config.ts`](../src/config/default-config.ts) file.
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
cdk deploy --all
```
### 3. Public Certificate Deployment (with External DNS Provider):
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
cdk deploy CertificateStack
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
cdk deploy RoleStack InstanceStack
```

### 4. Using an Existing Certificate:
Change the configuration in the [`src/config/default-config.ts`](../src/config/default-config.ts) file.
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
cdk deploy --all
```

## Deployment
The stacks can be deployed individually or together based on your needs. Required parameters vary by stack:

### Deploy all stacks:
```bash
cdk deploy --all
```

### Deploy individual (or multiple) stacks:
```bash
cdk deploy <stack_name_1> <stack_name_2> ...
```

## Cleanup
### Cleanup all stacks (and their associated resources):
```bash
cdk destroy --all
```

### Cleanup an individual stack:
```bash
cdk destroy <stack_name> 
```