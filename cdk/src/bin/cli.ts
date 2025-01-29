#!/usr/bin/env node

import { Command } from 'commander';
import { NitroEnclavesAcmStreamlineConfig } from '../config/types';
import { NitroEnclavesAcmStreamline } from './nitro_enclaves_acm_streamline';

const program = new Command();

program
  .name('setup-tool')
  .description('CLI tool for configuring and deploying the Nitro Enclaves ACM Setup')
  .version('1.0.0');

program
  // argument for a subcommand that is either deploy or destroy
  .argument('<subcommand>', 'Subcommand to execute deploy or destroy (deploy | destroy)')
  // Setup Name
  .requiredOption('-S, --setup-name <string>', 'Name of the setup')
  // Certificate config
  .option('-n, --certificate-name <string>', 'Certificate name')
  .option('-d, --domain-name <string>', 'Domain name for the certificate', 'example.com')
  .option('--is-private', 'Whether the certificate is private')
  .option('-z, --hosted-zone-id <string>', 'Route53 hosted zone ID')
  .option('-v, --validation-type <string>', 'Certificate validation type (DNS or EMAIL)')
  .option('-c, --certificate-arn <string>', 'Existing certificate ARN')
  .option('-p, --pca-arn <string>', 'Private Certificate Authority ARN')
  // Role config
  .option('-r, --role-name <string>', 'Role name')
  // Instance config
  .option('-i, --instance-name <string>', 'Instance name')
  .option('-k, --key-pair-name <string>', 'Key pair name', 'my-key-pair-name')
  .option('-s, --web-server-type <string>', 'Server type (NGINX or APACHE)')
  .option('-t, --instance-type <string>', 'Instance type')
  .option('-m, --ami-type <string>', 'AMI type (AL2 or AL2023)')
  // General config
  .option('-a, --aws-region <string>', 'AWS region')
  .option('-u, --aws-account-id <string>', 'AWS account ID')

program.parse(process.argv);

const options = program.opts<{
  setupName: string;
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
  webServerType: 'NGINX' | 'APACHE';
  amiType: 'AL2' | 'AL2023';
  instanceType: string;
  // General config
  awsRegion: string;
  awsAccountId: string;
}>();

const config: NitroEnclavesAcmStreamlineConfig = {
  certificateConfig: {
    stackName: `${options.setupName!}-CertificateStack`,
    domainName: options.domainName!,
    isPrivate: options.isPrivate || false,
    certificateName: options.certificateName || 'AcmneCertificate',
    existingCertificateArn: options.certificateArn,
    hostedZoneId: options.hostedZoneId,
    validationType: options.validationType,
    pcaArn: options.pcaArn,
  },
  roleConfig: {
    stackName: `${options.setupName!}-RoleStack`,
    roleName: options.roleName || 'AcmneRole',
  },
  instanceConfig: {
    stackName: `${options.setupName!}-InstanceStack`,
    instanceName: options.instanceName || 'AcmneInstance',
    keyPairName: options.keyPairName!,
    instanceType: options.instanceType || 'c5.xlarge',
    serverType: options.webServerType || 'NGINX',
    amiType: options.amiType || 'AL2023',
  },
  region: options.awsRegion || 'us-east-1',
  account: options.awsAccountId!,
};

const isDestroySubcommand = program.args[0] === 'destroy';

console.log('ACM for Nitro Enclaves configuration:\n', config)
const streamline = new NitroEnclavesAcmStreamline(config, isDestroySubcommand);
streamline.deploy();