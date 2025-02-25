// config/types.ts
export interface NitroEnclavesAcmStreamlineConfig {
    certificateConfig: {
      stackName: string;
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
      stackName: string;
      roleName?: string;
    };
    instanceConfig: {
      stackName: string;
      instanceName?: string;
      keyPairName: string;
      serverType: 'NGINX' | 'APACHE';
      amiType: 'AL2' | 'AL2023';
      instanceType: string;
      encryptVolume: boolean;
      allowSSHPort: boolean;
    };
    region: string;
    account: string;
  }
  