// config/config-validator.ts
import { NitroEnclavesAcmStreamlineConfig } from './types';

export class ConfigValidator {
    static validate(config: NitroEnclavesAcmStreamlineConfig): void {
        if (!config.region) throw new Error('AWS region must be specified.');
        if (!config.account) throw new Error('AWS account must be specified.');
        if (!config.instanceConfig.keyPairName) throw new Error('EC2 Key pair name must be specified.');

        if (!config.certificateConfig.existingCertificateArn) {
            if (config.certificateConfig.isPrivate) {
                if (!config.certificateConfig.pcaArn) {
                    throw new Error('Private certificates require a PCA ARN.');
                }
            } else {
                if (!config.certificateConfig.validationType && !config.certificateConfig.hostedZoneId) {
                    throw new Error('Public certificates require a hostedZoneId (if using Route53 as a DNS provider), or a validationType.');
                }
            }
        }
    }
}
