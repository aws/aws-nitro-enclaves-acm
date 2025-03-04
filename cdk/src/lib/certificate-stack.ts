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

    let certificate = null;

    // Provision a public certificate
    if (!props?.isPrivate) {
      // If route53 is the DNS provider, validation is done automatically
      if (props?.hostedZoneId) {
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
    new cdk.CfnOutput(this, 'DomainName', { value: props!.domainName });
  }
}
