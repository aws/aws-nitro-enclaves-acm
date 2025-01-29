#!/usr/bin/env node
import * as cdk from 'aws-cdk-lib';
import { CertificateStack } from '../lib/certificate-stack';
import { RoleStack } from '../lib/role-stack';
import { InstanceStack } from '../lib/instance-stack';
import { getDefaultConfig } from '../config/default-config';
import { ConfigValidator } from '../config/config-validator';
import { NitroEnclavesAcmStreamlineConfig } from '../config/types';

require('dotenv').config();

export class NitroEnclavesAcmStreamline {
  private readonly app: cdk.App;
  private readonly config: NitroEnclavesAcmStreamlineConfig;
  private readonly isDestroySubcommand: boolean;
  private certificateArn: string = '';

  constructor(config: NitroEnclavesAcmStreamlineConfig, isDestroySubcommand: boolean = false) {
    this.app = new cdk.App();
    this.config = config;
    this.isDestroySubcommand = isDestroySubcommand;
    ConfigValidator.validateEnv(this.config, this.isDestroySubcommand);
  }

  private createCertificateStack(): void {
    if (!this.config.certificateConfig?.existingCertificateArn) {
      ConfigValidator.validateCertificateStack(this.config, this.isDestroySubcommand);
      const certificateStack = new CertificateStack(
        this.app,
        this.config.certificateConfig.stackName || 'CertificateStack',
        {
          env: this.getEnv(),
          domainName: this.config.certificateConfig.domainName,
          hostedZoneId: this.config.certificateConfig.hostedZoneId,
          isPrivate: this.config.certificateConfig.isPrivate,
          pcaArn: this.config.certificateConfig.pcaArn,
          certificateName: this.config.certificateConfig.certificateName || 'AcmneCertificate',
          validationType: this.config.certificateConfig.validationType,
        });
      this.certificateArn = certificateStack.certificateArn;
    } else {
      this.certificateArn = this.config.certificateConfig.existingCertificateArn;
    }
  }

  private createRoleStack(): RoleStack {
    ConfigValidator.validateRoleStack(this.config, this.isDestroySubcommand);
    return new RoleStack(
      this.app,
      this.config.roleConfig?.stackName || 'RoleStack',
      {
        env: this.getEnv(),
        certificateArn: this.certificateArn,
        roleName: this.config.roleConfig?.roleName || 'AcmneRole',
      });
  }

  private createInstanceStack(roleStack: RoleStack): InstanceStack {
    ConfigValidator.validateInstanceStack(this.config, this.isDestroySubcommand);
    return new InstanceStack(
      this.app,
      `${this.config.instanceConfig.stackName}` || `InstanceStack`,
      {
        env: this.getEnv(),
        roleArn: roleStack.roleArn,
        keyPairName: this.config.instanceConfig.keyPairName,
        serverType: this.config.instanceConfig.serverType,
        amiType: this.config.instanceConfig.amiType,
        instanceType: this.config.instanceConfig.instanceType,
        instanceName: this.config.instanceConfig.instanceName || 'AcmneInstance',
        certificateArn: this.certificateArn,
        domainName: this.config.certificateConfig.domainName,
        isCertificatePrivate: this.config.certificateConfig.isPrivate,
      }
    );
  }

  private getEnv(): { account: string; region: string } {
    return {
      account: this.config.account,
      region: this.config.region
    };
  }

  public deploy(): void {
    this.createCertificateStack();
    const roleStack = this.createRoleStack();
    const instanceStack = this.createInstanceStack(roleStack);
    instanceStack.addDependency(roleStack);
  }
}

const streamline = new NitroEnclavesAcmStreamline(getDefaultConfig());
streamline.deploy();
