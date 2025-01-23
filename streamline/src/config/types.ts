// config/types.ts
export interface NitroEnclavesAcmStreamlineConfig {
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
  