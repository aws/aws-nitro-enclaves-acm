import * as cdk from 'aws-cdk-lib';
import * as acm from 'aws-cdk-lib/aws-certificatemanager';
import * as route53 from 'aws-cdk-lib/aws-route53';
import * as acmpca from 'aws-cdk-lib/aws-acmpca';
import { Construct } from 'constructs';

/*
  Step 1 - Create the ACM certificate: https://docs.aws.amazon.com/enclaves/latest/user/install-acm.html#create-cert 
*/

interface CertificateStackProps extends cdk.StackProps {
  certificateName?: string;
  // Required props
  domainName: string;
  isPrivate: boolean;
  // Public certificate only
  hostedZoneId?: string; // If Route53 is the DNS provider
  validationType?: 'DNS' | 'EMAIL'; // Otherwise
  // Private certificate only
  pcaArn?: string;
}

export class CertificateStack extends cdk.Stack {
  public readonly certificateArn: string;

  constructor(scope: Construct, id: string, props?: CertificateStackProps) {
    super(scope, id, props);

    // Props validation
    if (!props?.domainName) {
      throw new Error('domainName is required in CertificateStack.');
    }

    if (!props?.isPrivate) {
      throw new Error('isPrivate is required in CertificateStack.');
    }

    if (props?.isPrivate) {
      // Validation for private certificates
      if (!props.pcaArn) {
        throw new Error('pcaArn is required for private certificates in CertificateStack.');
      }
      if (props.validationType) {
        throw new Error('validationType should not be specified for private certificates in CertificateStack.');
      }
      if (props.hostedZoneId) {
        throw new Error('hostedZoneId should not be specified for private certificates in CertificateStack.');
      }
    } else {
      if (props?.pcaArn) {
        throw new Error('pcaArn should not be specified for public certificates in CertificateStack.');
      }
      // Validation for public certificates
      if (props?.hostedZoneId && props?.validationType) {
        throw new Error('validationType should not be specified when Route53 is the DNS provider (hostedZoneId is present) in CertificateStack.');
      }
      if (!props?.hostedZoneId && !props?.validationType) {
        throw new Error('Either hostedZoneId or validationType must be specified for public certificates in CertificateStack.');
      }
      if (props?.validationType && !['DNS', 'EMAIL'].includes(props.validationType)) {
        throw new Error('validationType must be either "DNS" or "EMAIL" in CertificateStack.');
      }
    }

    let certificate = null;

    // Provision a public certificate
    if (!props?.isPrivate) {
      // If route53 is the DNS provider, validation is done automatically
      if (props.hostedZoneId) {
        const hostedZone = route53.HostedZone.fromHostedZoneId(this, 'HostedZone', props?.hostedZoneId!);
        certificate = new acm.Certificate(this, props?.certificateName!, {
          domainName: props?.domainName!,
          validation: acm.CertificateValidation.fromDns(hostedZone),
        });
      } else {
        certificate = new acm.Certificate(this, props?.certificateName!, {
          domainName: props?.domainName!,
          validation: props?.validationType === 'DNS' ? acm.CertificateValidation.fromDns() : acm.CertificateValidation.fromEmail(),
        });
      }
    } else {
      certificate = new acm.PrivateCertificate(this, props?.certificateName!, {
        domainName: props?.domainName!,
        certificateAuthority: acmpca.CertificateAuthority.fromCertificateAuthorityArn(this, 'CertificateAuthority', props?.pcaArn!),
      });
    }

    this.certificateArn = certificate.certificateArn;

    new cdk.CfnOutput(this, 'CertificateArn', { value: this.certificateArn });
    new cdk.CfnOutput(this, 'DomainName', { value: props.domainName });
  }
}
