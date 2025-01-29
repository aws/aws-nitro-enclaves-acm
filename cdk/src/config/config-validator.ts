// config/config-validator.ts
import { NitroEnclavesAcmStreamlineConfig } from './types';

export class ConfigValidator {
    static validateCertificateStack(config: NitroEnclavesAcmStreamlineConfig, isDestroySubcommand: boolean = false): void {
        if (!isDestroySubcommand) {
            if (!config.certificateConfig.existingCertificateArn) {
                if (!config.certificateConfig?.domainName) {
                    throw new Error('domainName is required in CertificateStack.');
                }

                if (config.certificateConfig?.isPrivate === undefined) {
                    throw new Error('isPrivate is required in CertificateStack.');
                }

                if (config.certificateConfig?.isPrivate) {
                    // Validation for private certificates
                    if (!config.certificateConfig.pcaArn) {
                        throw new Error('pcaArn is required for private certificates in CertificateStack.');
                    }
                    if (config.certificateConfig.validationType) {
                        throw new Error('validationType should not be specified for private certificates in CertificateStack.');
                    }
                    if (config.certificateConfig.hostedZoneId) {
                        throw new Error('hostedZoneId should not be specified for private certificates in CertificateStack.');
                    }
                } else {
                    if (config.certificateConfig?.pcaArn) {
                        throw new Error('pcaArn should not be specified for public certificates in CertificateStack.');
                    }
                    // Validation for public certificates
                    if (config.certificateConfig?.hostedZoneId && config.certificateConfig?.validationType) {
                        throw new Error('validationType should not be specified when Route53 is the DNS provider (hostedZoneId is present) in CertificateStack.');
                    }
                    if (!config.certificateConfig?.hostedZoneId && !config.certificateConfig?.validationType) {
                        throw new Error('Either hostedZoneId or validationType must be specified for public certificates in CertificateStack.');
                    }
                    if (config.certificateConfig?.validationType && !['DNS', 'EMAIL'].includes(config.certificateConfig.validationType)) {
                        throw new Error('validationType must be either "DNS" or "EMAIL" in CertificateStack.');
                    }
                }
            }
        }
    }

    static validateRoleStack(config: NitroEnclavesAcmStreamlineConfig, isDestroySubcommand: boolean = false): void {
        // Insert additional RoleStack validation if needed
        return
    }

    static validateInstanceStack(config: NitroEnclavesAcmStreamlineConfig, isDestroySubcommand: boolean = false): void {
        if (!isDestroySubcommand) {
            if (!['NGINX', 'APACHE'].includes(config.instanceConfig?.serverType!)) {
                throw new Error('Invalid server type. Must be NGINX or APACHE.')
            }
            if (!['AL2', 'AL2023'].includes(config.instanceConfig?.amiType!)) {
                throw new Error('Invalid AMI type. Must be AL2 or AL2023.')
            }
            if (!config.instanceConfig?.keyPairName) {
                throw new Error('EC2 keyPairName is required in InstanceStack.')
            }
            if (!config.instanceConfig?.instanceType) {
                throw new Error('instanceType is required in InstanceStack.')
            }
        }

    }

    static validateEnv(config: NitroEnclavesAcmStreamlineConfig, isDestroySubcommand: boolean = false): void {
        if (!config.region) throw new Error('AWS region must be specified.');
        if (!config.account) throw new Error('AWS account must be specified.');
    }
}
