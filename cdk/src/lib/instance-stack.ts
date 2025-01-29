import * as cdk from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2'
import * as iam from 'aws-cdk-lib/aws-iam'
import { Construct } from 'constructs';
import { readFileSync } from 'fs';

/*
  Step 2 - Prepare the enclave-enabled parent instance: https://docs.aws.amazon.com/enclaves/latest/user/install-acm.html#prepare-instance
  Step 6 - Attach the role to the instance: https://docs.aws.amazon.com/enclaves/latest/user/install-acm.html#instance-role
*/

interface InstanceStackProps extends cdk.StackProps {
  instanceName?: string;
  roleArn: string;
  keyPairName: string;
  serverType: 'NGINX' | 'APACHE';
  amiType: 'AL2' | 'AL2023';
  instanceType: string;
  certificateArn: string;
  domainName: string;
  isCertificatePrivate: boolean;
}

export class InstanceStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: InstanceStackProps) {
    super(scope, id, props);

    // Step 2: Prepare the enclave-enabled parent instance
    const vpc = ec2.Vpc.fromLookup(this, `DefaultVPC-${props.instanceName}`, { isDefault: true })

    const securityGroup = new ec2.SecurityGroup(this, `InstanceSecurityGroup-${props.instanceName}`, {
      vpc,
      description: 'Allow SSH (TCP port 22) and HTTP/HTTPS (TCP ports 80/443) in',
      allowAllOutbound: true
    });

    securityGroup.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(22), 'Allow SSH Access');
    securityGroup.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(80), 'Allow HTTP Access');
    securityGroup.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(443), 'Allow HTTPS Access');

    // Configure user data (startup commands) based on AMI type and server type
    const userData = ec2.UserData.custom(this.getUserDataConfig(props));

    // Configure instance type
    const instanceType = new ec2.InstanceType(props.instanceType);
    const isArm = instanceType.architecture === ec2.InstanceArchitecture.ARM_64;

    // Configure AMI
    const machineImage = new ec2.AmazonLinuxImage({
      generation: props?.amiType === 'AL2'
        ? ec2.AmazonLinuxGeneration.AMAZON_LINUX_2
        : ec2.AmazonLinuxGeneration.AMAZON_LINUX_2023,
      cpuType: isArm
        ? ec2.AmazonLinuxCpuType.ARM_64
        : ec2.AmazonLinuxCpuType.X86_64
    });

    // Step 6 - Attach the role to the instance
    const role = iam.Role.fromRoleArn(this, `ImportedRole-${props.instanceName}`, props?.roleArn!);
    const instanceProfile = new iam.InstanceProfile(this, `AcmInstanceProfile-${props.instanceName}`, { role: role });

    // Step 2 & Step 6 - Create the enclave-enabled instance with the attached role/instance profile
    const instance = new ec2.Instance(this, props?.instanceName!, {
      instanceType: instanceType,
      machineImage: machineImage,
      vpc: vpc,
      vpcSubnets: { subnetType: ec2.SubnetType.PUBLIC },
      securityGroup: securityGroup,
      keyPair: ec2.KeyPair.fromKeyPairName(this, `KeyPair-${props.instanceName}`, props?.keyPairName!),
      instanceProfile: instanceProfile,
      enclaveEnabled: true,
      userData: userData
    });

    // Outputs: Instance Information
    new cdk.CfnOutput(this, 'InstanceId', { value: instance.instanceId });
    new cdk.CfnOutput(this, 'InstancePublicIP', { value: instance.instancePublicIp });
    new cdk.CfnOutput(this, 'InstancePublicDnsName', { value: instance.instancePublicDnsName });
    new cdk.CfnOutput(this, 'keyPairName', { value: props?.keyPairName });
    new cdk.CfnOutput(this, 'serverType', { value: props?.serverType })
    new cdk.CfnOutput(this, 'amiType', { value: props?.amiType })
    new cdk.CfnOutput(this, 'SSH connection string', { value: `ssh -i ${props?.keyPairName!}.pem ec2-user@${instance.instancePublicDnsName}` });
  }
  // Get commands for user data 
  private getUserDataConfig(props: InstanceStackProps, userDataScriptsFolder: string = 'src/assets/user-data-scripts'): string {
    const mainConfig = readFileSync(`${userDataScriptsFolder}/${props.amiType}/${props.serverType.toLowerCase()}-conf.sh`, 'utf8')
    const privateCertConfig = props.isCertificatePrivate ? readFileSync(`${userDataScriptsFolder}/private-cert-conf.sh`, 'utf8') : ''
    const combinedConfig = `${mainConfig}\n${privateCertConfig}`
      .replaceAll('CERTIFICATE_ARN_PLACEHOLDER', props.certificateArn)
      .replaceAll('DOMAIN_NAME_PLACEHOLDER', props.domainName)
    return combinedConfig
  }
}
