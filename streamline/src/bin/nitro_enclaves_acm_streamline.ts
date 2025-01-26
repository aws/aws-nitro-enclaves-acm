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
  private certificateArn: string = '';

  constructor(config: NitroEnclavesAcmStreamlineConfig) {
    this.app = new cdk.App();
    this.config = config;
    ConfigValidator.validate(this.config);
  }

  private createCertificateStack(): void {
    if (!this.config.certificateConfig?.existingCertificateArn) {
      const certificateStack = new CertificateStack(this.app, 'CertificateStack', {
        env: this.getEnv(),
        domainName: this.config.certificateConfig.domainName,
        hostedZoneId: this.config.certificateConfig.hostedZoneId,
        isPrivate: this.config.certificateConfig.isPrivate,
        pcaArn: this.config.certificateConfig.pcaArn,
        certificateName: this.config.certificateConfig.certificateName || 'AcmneCertificate',
      });
      this.certificateArn = certificateStack.certificateArn;
    } else {
      this.certificateArn = this.config.certificateConfig.existingCertificateArn;
    }
  }

  private createRoleStack(): RoleStack {
    return new RoleStack(this.app, 'RoleStack', {
      env: this.getEnv(),
      certificateArn: this.certificateArn,
      roleName: this.config.roleConfig?.roleName || 'AcmneRole',
    });
  }

  private createInstanceStack(roleStack: RoleStack): InstanceStack {
    return new InstanceStack(
      this.app, 
      `InstanceStack-${this.config.instanceConfig.amiType}-${this.config.instanceConfig.serverType}`,
      {
        env: this.getEnv(),
        roleArn: roleStack.roleArn,
        keyPairName: this.config.instanceConfig.keyPairName,
        serverType: this.config.instanceConfig.serverType,
        amiType: this.config.instanceConfig.amiType,
        instanceType: this.config.instanceConfig.instanceType,
        instanceName: this.config.instanceConfig.instanceName || 'AcmneInstance',
        certificateArn: this.certificateArn,
        domainName: this.config.certificateConfig.domainName
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
