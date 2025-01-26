#!/usr/bin/env node

import { Command } from 'commander';
import { NitroEnclavesAcmStreamlineConfig } from '../config/types';
import { NitroEnclavesAcmStreamline } from './nitro_enclaves_acm_streamline';

const program = new Command();

program
  .name('acmne-cli')
  .description('CLI for configuring and deploying the Nitro Enclaves ACM Streamline')
  .version('1.0.0');

program
  // Certificate config
  .option('-n, --certificate-name <string>', 'Certificate name')
  .option('-d, --domain-name <string>', 'Domain name for the certificate')
  .option('--is-private', 'Whether the certificate is private')
  .option('-z, --hosted-zone-id <string>', 'Route53 hosted zone ID')
  .option('-v, --validation-type <string>', 'Certificate validation type (DNS or EMAIL)')
  .option('-c, --certificate-arn <string>', 'Existing certificate ARN')
  .option('-p, --pca-arn <string>', 'Private Certificate Authority ARN')
  // Role config
  .option('-r, --role-name <string>', 'Role name')
  // Instance config
  .option('-i, --instance-name <string>', 'Instance name')
  .option('-k, --key-pair-name <string>', 'Key pair name')
  .option('-s, --server-type <string>', 'Server type (NGINX or APACHE)')
  .option('-t, --instance-type <string>', 'Instance type')
  .option('-m, --ami-type <string>', 'AMI type (AL2 or AL2023)')
  // General config
  .option('-a, --aws-region <string>', 'AWS region')
  .option('-u, --aws-account <string>', 'AWS account');

program.parse(process.argv);

const options = program.opts<{
  // Certificate config
  certificateName?: string;
  domainName: string;
  isPrivate: boolean;
  hostedZoneId?: string;
  validationType?: 'DNS' | 'EMAIL';
  certificateArn?: string;
  pcaArn?: string;
  // Role config
  roleName?: string;
  // Instance config
  instanceName?: string;
  keyPairName: string;
  serverType: 'NGINX' | 'APACHE';
  amiType: 'AL2' | 'AL2023';
  instanceType: string;
  // General config
  awsRegion: string;
  awsAccount: string;
}>();

const config: NitroEnclavesAcmStreamlineConfig = {
  certificateConfig: {
    domainName: options.domainName!,
    isPrivate: options.isPrivate || false,
    certificateName: options.certificateName || 'AcmneCertificate',
    existingCertificateArn: options.certificateArn,
    hostedZoneId: options.hostedZoneId,
    validationType: options.validationType,
    pcaArn: options.pcaArn,
  },
  roleConfig: {
    roleName: options.roleName || 'AcmneRole',
  },
  instanceConfig: {
    instanceName: options.instanceName || 'AcmneInstance',
    keyPairName: options.keyPairName!,
    instanceType: options.instanceType || 'c5.xlarge',
    serverType: options.serverType || 'NGINX',
    amiType: options.amiType || 'AL2023',
  },
  region: options.awsRegion || 'us-east-1',
  account: options.awsAccount!,
};

console.log('ACM for Nitro Enclaves configuration:\n', config)
const streamline = new NitroEnclavesAcmStreamline(config);
streamline.deploy();