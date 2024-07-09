"""EKS Cluster Setup."""
import argparse
import base64
import os
import time
from os.path import expanduser
from typing import List, Optional

import arnparse
import boto3
import botocore
import yaml
from kubernetes import client
from kubernetes import config

# userData attached with the launch configuration to be run on starting of the
# worker nodes.
# We perform following operations:
#   1. Update the hostname of the node. Kubernetes uses hostname as label and
#      hence requires it to be restricted to 63 chars. If the hostname is
#      greater than 63 chars, we update the hostname to default hostname.
#   2. Create 255 loop devices. Loop devices are used by CDM indexing code.
#      This ensures that each pod has access to enough loop devices. Earlier
#      we tried created loop devices inside the pod rather than at node startup,
#      but that lead to errors in finding loop devices which is hypothesised to
#      be due to multiple pods trying to create loop devices concurrently.
#   3. Run EKS bootstrap script which starts kubelet and register the node
#      with the EKS master.
USER_DATA_FORMAT = '''
#!/bin/bash
set -o xtrace

host=$(hostname)
if [[ ${#host} -gt 63 ]]; then
    hostnamectl set-hostname $(hostname | cut -d "." -f 1).%s
fi

# Create loop devices, this is taken from CDM code:
# src/scripts/vmdkmount/make_loop.sh
NUM_LOOP_DEVICES=255
LOOP_REF="/dev/loop0"
if [ ! -e $LOOP_REF ]; then
    /sbin/losetup -f
fi

for ((i = 1; i < $NUM_LOOP_DEVICES; i++)); do
  if [ -e /dev/loop$i ]; then
    continue;
  fi
  mknod /dev/loop$i b 7 $i;
  chown --reference=$LOOP_REF /dev/loop$i;
  chmod --reference=$LOOP_REF /dev/loop$i;
done

# Remove LVM on host, just to avoid any interference with containers.
yum remove -y lvm2

# Source the env variables before running the bootstrap.sh script
set -a
source /etc/environment

# https://github.com/awslabs/amazon-eks-ami/blob/master/files/bootstrap.sh
/etc/eks/bootstrap.sh %s --b64-cluster-ca %s --apiserver-endpoint %s
'''

# userData attached with the launch configuration to be run on starting of the
# worker nodes with Network Proxy configuration.
# We perform following operations in the cloud boothook:
# 1. Setup the /etc/environment with the proxy config
# 2. Create the docker service dir
# 3. Setup the proxy config in yum, docker and kubelet services
# 4. Reload the docker and kubelet daemon

# We perform the operations in the shell script as described in the
# userDataFormat formatted string above.
# Ref: https://aws.amazon.com/premiumsupport/knowledge-center/eks-http-proxy-configuration-automation/
USER_DATA_NW_PROXY_FORMAT = '''
Content-Type: multipart/mixed; boundary="==BOUNDARY=="
MIME-Version:  1.0
--==BOUNDARY==
Content-Type: text/cloud-boothook; charset="us-ascii"

#Set the proxy endpoints
PROXY="%s"
PROXY_SSL="%s"
NO_PROXY_ENDPOINTS="%s"

%s

#Create the docker systemd directory
mkdir -p /etc/systemd/system/docker.service.d

#Configure yum to use the proxy
cloud-init-per instance yum_proxy_config cat << EOF >> /etc/yum.conf
proxy=$PROXY
EOF

#Set the proxy for future processes, and use as an include file
cloud-init-per instance proxy_config cat << EOF >> /etc/environment
http_proxy=$PROXY
https_proxy=$PROXY_SSL
HTTP_PROXY=$PROXY
HTTPS_PROXY=$PROXY_SSL
no_proxy=$VPC_CIDR,$NO_PROXY_ENDPOINTS
NO_PROXY=$VPC_CIDR,$NO_PROXY_ENDPOINTS
EOF

#Configure docker with the proxy
cloud-init-per instance docker_proxy_config tee <<EOF /etc/systemd/system/docker.service.d/proxy.conf >/dev/null
[Service]
EnvironmentFile=/etc/environment
EOF

#Configure the kubelet with the proxy
cloud-init-per instance kubelet_proxy_config tee <<EOF /etc/systemd/system/kubelet.service.d/proxy.conf >/dev/null
[Service]
EnvironmentFile=/etc/environment
EOF

#Reload the daemon and restart docker to reflect proxy configuration at launch of instance
cloud-init-per instance reload_daemon systemctl daemon-reload
cloud-init-per instance enable_docker systemctl enable --now --no-block docker

--==BOUNDARY==
Content-Type:text/x-shellscript; charset="us-ascii"
%s
--==BOUNDARY==--
'''

# metadataAPIRequestWithToken fetches instance metadata using IMDSv2
# Instance can enable it by setting,
# 'HttpTokens' to 'required' and 'HttpPutResponseHopLimit' to '2'.
metadata_api_request_with_token = '''
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
MAC=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" -s http://169.254.169.254/latest/meta-data/mac/)
VPC_CIDR=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" -s http://169.254.169.254/latest/meta-data/network/interfaces/macs/$MAC/vpc-ipv4-cidr-blocks | xargs | tr ' ' ',')
'''

# metadataAPIRequestWithoutToken fetches instance metadata using IMDSv1
metadata_api_request_without_token = '''
MAC=$(curl -s http://169.254.169.254/latest/meta-data/mac/)
VPC_CIDR=$(curl -s http://169.254.169.254/latest/meta-data/network/interfaces/macs/$MAC/vpc-ipv4-cidr-blocks | xargs | tr ' ' ',')
'''

# RSC Deployment IPs
RSC_DEPLOYMENT_IPS: List[str] = ["ip1", "ip2"]
PUBLIC_INTERNET_CIDR = "0.0.0.0/0"
EKSK8s_VERSION = "1.29"
NODE_TYPE = "m5.2xlarge"
ARN_PREFIX = "arn:"
ARN_DELIMITER = ":"
KUBE_SYSTEM_NAMESPACE = "kube-system"
CONFIG_MAP_NAME = "aws-auth"
MAP_ROLES_DATA_KEY = "mapRoles"
MAP_ROLE_DATA_FORMAT = """
- rolearn: %s
  username: system:node:{{EC2PrivateDNSName}}
  groups:
    - system:bootstrappers
    - system:nodes
- rolearn: %s
  username: rubrik
  groups:
    - system:masters
"""


class AwsHypervisorManager:
    """AWS Hypervisor Manager class."""

    def __init__(
            self,
            access_key_id: str,
            secret_key_id: str,
            session_token: str,
            region: str
    ):
        """Create a hypervisor manager for AWS.

        Args:
            access_key_id: Str representing the AWS access key ID.
            secret_key_id: Str representing the AWS secret key ID.
            session_token: Str representing the AWS session token.
            region: Str representing AWS region.
        """
        self.access_key_id = access_key_id
        self.secret_key_id = secret_key_id
        self.session_token = session_token
        self.region = region
        self.session = boto3.session.Session
        # AWS STS
        self.sts: boto3.client.Client = boto3.client(
            'sts',
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_key_id,
            aws_session_token=session_token,
        )
        self.iam: boto3.client.Client = boto3.client(
            'iam',
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_key_id,
            aws_session_token=session_token,
        )
        self.__session(region)
        # Add dict and lock for other services as needed

    def __session(self, region: str) -> boto3.session.Session:
        """Returns the boto3 session object for this region.

        Args:
        Returns:
            Boto3 Session object in the region.
        """
        print(f'Creating session for region: {region}')
        self.session = boto3.session.Session(
            region_name=self.region,
            aws_access_key_id=self.access_key_id,
            aws_secret_access_key=self.secret_key_id,
            aws_session_token=self.session_token,
        )
        return self.session

    @property
    def __ec2_client(self) -> botocore.client.BaseClient:
        """Returns the AWS EC2 client.

        Args:
        Returns:
            AWS EC2 client for the region.
        """
        return self.session.client('ec2')

    @property
    def __eks_client(self) -> botocore.client.BaseClient:
        """Returns the AWS EKS client.

        Args:
        Returns:
            AWS EKS client for the region.
        """
        return self.session.client('eks')

    @property
    def __ssm_client(self) -> botocore.client.BaseClient:
        """Returns the AWS SSM client.

        Args:
        Returns:
            AWS SSM client for the region.
        """
        return self.session.client('ssm')

    @property
    def __autoscaling_client(self) -> botocore.client.BaseClient:
        """Returns the AWS AutoScaling client.

        Args:
        Returns:
            AWS AutoScaling client for the region.
        """
        return self.session.client('autoscaling')

    @property
    def __ec2(self) -> boto3.resources.base.ServiceResource:
        """Returns the AWS EC2 resource.

        Args:
        Returns:
            AWS EC2 resource for the region.
        """
        return self.session.resource('ec2')

    @property
    def aws_account_id(self) -> str:
        """Returns the AWS Account ID for the corresponding hypervisor manager.

        Returns:
            AWS CloudFormation resource for the region.
        """
        return str(self.sts.get_caller_identity().get('Account'))

    def create_security_group(
            self,
            name: str,
            description: str,
            vpc_id: str,
            tag_specifications: List[dict] = []
    ) -> str:
        """Creates security group

        Args:
            name: Name of security group
            description: Description for security group
            vpc_id: VPC ID for security group
            tag_specifications: tags to assign to security group
        Returns:
            security group ID
        """
        print(f"Creating security group {name}")
        resp = self.__ec2_client.create_security_group(
            GroupName=name,
            Description=description,
            VpcId=vpc_id,
            TagSpecifications=tag_specifications,
        )
        print(f"Created security group {name}: {resp['GroupId']}")
        return str(resp['GroupId'])

    @staticmethod
    def get_security_group_ip_permission(
            description: str,
            security_group_id: str,
            ip_protocol: str,
            from_port: Optional[int] = None,
            to_port: Optional[int] = None,
    ) -> dict:
        """

        Args:
            description: Description for IP permission
            from_port: Start of port range
            to_port: End of the port range
            security_group_id: Destination/Source security group id
            ip_protocol: The IP protocol name e.g. tcp, udp, icmp etc.
        Returns:
            dict of ip_permission
        """
        ip_permission = {
            'IpProtocol':
                ip_protocol,
            'UserIdGroupPairs': [{
                'GroupId': security_group_id,
                'Description': description,
            }]
        }
        if to_port:
            ip_permission['ToPort'] = to_port
        if from_port:
            ip_permission['FromPort'] = from_port
        return ip_permission

    def authorize_security_group_ingress(
            self, group_id: str, ip_permissions: List[dict]
    ) -> None:
        """Authorizes ingress for security group

        Args:
            group_id: Security group id
            ip_permissions: The sets of IP permissions
        Returns:
            None
        """
        print(f"Authorizing ingress for security group {group_id}")
        try:
            self.__ec2_client.authorize_security_group_ingress(
                GroupId=group_id,
                IpPermissions=ip_permissions,
            )
            print(f"Ingress authorized for security group {group_id}")
        except botocore.exceptions.ClientError as e:
            print(f"Error authorizing security group ingress: {str(e)}")
            raise

    def authorize_security_group_egress(
            self, group_id: str, ip_permissions: List[dict]
    ) -> None:
        """Authorizes egress for security group

        Args:
            group_id: Security group id
            ip_permissions: The sets of IP permissions
        Returns:
            None
        """
        print(f"Authorizing egress for security group {group_id}")
        try:
            self.__ec2_client.authorize_security_group_egress(
                GroupId=group_id,
                IpPermissions=ip_permissions,
            )
            print(f"Egress authorized for security group {group_id}")
        except botocore.exceptions.ClientError as e:
            print(f"Error authorizing security group egress: {str(e)}")
            raise

    def create_cluster(
            self,
            name: str,
            version: str,
            role_arn: str,
            subnet_ids: List[str],
            cluster_security_group_id: str,
            cluster_private_endpoint_enabled: bool,
            public_access_cidrs: List[str]
    ) -> (str, str, str, str):
        """Creates EKS cluster

             Args:
                 name: name of the EKS cluster
                 version: desired Kubernetes version for your cluster
                 role_arn: ARN of IAM role for permissions to kubernetes control plane
                 subnet_ids: subnets for EKS nodes
                 cluster_security_group_id: security group for cluster plane
                 cluster_private_endpoint_enabled: enable private endpoint for the cluster
                 public_access_cidrs: public access CIDRs
             Returns:
                 cluster name, endpoint, certificateAuthority
         """
        print(f"Creating EKS cluster {name}")
        enable_public_access = bool(public_access_cidrs)
        resources_vpc_config = {
            'subnetIds': subnet_ids,
            'securityGroupIds': [cluster_security_group_id],
            'endpointPublicAccess': enable_public_access,
            'endpointPrivateAccess': cluster_private_endpoint_enabled,
            'publicAccessCidrs': public_access_cidrs,
        }
        try:
            resp = self.__eks_client.create_cluster(
                name=name,
                version=version,
                roleArn=role_arn,
                resourcesVpcConfig=resources_vpc_config,
            )
            timeout = time.time() + 60 * 20  # 20 minutes from now
            while True:
                resp = self.__eks_client.describe_cluster(name=name)
                if resp['cluster']['status'] == 'ACTIVE' or time.time(
                ) > timeout:
                    break
                time.sleep(60)  # sleep for a minute
            print(f"Created EKS cluster {name}: {resp}")

            if resp['cluster']['status'] != 'ACTIVE':
                raise Exception(
                    "Cluster status is not ACTIVE: %s",
                    resp['cluster']['status']
                )

            return (
                resp["cluster"]["name"],
                resp["cluster"]["arn"],
                resp["cluster"]["endpoint"],
                resp["cluster"]["certificateAuthority"]["data"]
            )
        except botocore.exceptions.ClientError as e:
            print(f"Error creating EKS cluster: {str(e)}")
            raise

    def get_eks_node_ami(self, eks_version: str) -> str:
        """Fetches the AWS recommended EKS worker node AMI ID
        https://docs.aws.amazon.com/eks/latest/userguide/eks-optimized-ami.html.

        Args:
            eks_version: EKS cluster version
        Returns:
            AMI ID for worker node
        """
        parameter_name = f'/aws/service/eks/optimized-ami/{eks_version}/amazon-linux-2/recommended/image_id'
        try:
            resp = self.__ssm_client.get_parameter(Name=parameter_name)
            return str(resp['Parameter']['Value'])
        except botocore.exceptions.ClientError as e:
            print(f"Error fetching EKS node AMI: {str(e)}")
            raise

    def create_launch_template(
            self,
            name: str,
            block_device_mappings: List,
            ami_id: str,
            node_type: str,
            user_data: str,
            instance_profile_arn: str,
            security_group: str,
            instance_metadata_options: dict,
            key_name: Optional[str] = None
    ) -> str:
        """Creates launch template for worker nodes

         Args:
             name: launch template name
             block_device_mappings: block device mapping for worker nodes
             ami_id: AMI ID for worker nodes
             node_type: node type
             user_data: user data for instance
             instance_profile_arn: The arn of the instance profile
             instance_metadata_options: The metadata options for the instance
             security_group: worker node security group ID
             key_name: name of the key pair
         Returns:
             launch template id
         """
        print(f"Creating launch template {name}")
        launch_template_data = {
            'BlockDeviceMappings': block_device_mappings,
            'ImageId': ami_id,
            'InstanceType': node_type,
            'UserData': user_data,
            'SecurityGroupIds': [security_group],
            'IamInstanceProfile': {
                'Arn': instance_profile_arn
            },
            'MetadataOptions': instance_metadata_options
        }
        if key_name:
            launch_template_data['KeyName'] = key_name
        try:
            resp = self.__ec2_client.create_launch_template(
                LaunchTemplateName=name,
                LaunchTemplateData=launch_template_data,
            )
            print(f"Created launch template {name}: {resp}")
            return str(resp['LaunchTemplate']['LaunchTemplateId'])
        except botocore.exceptions.ClientError as e:
            print(f"Error creating launch template: {str(e)}")
            raise

    def create_autoscaling_group(
            self,
            name: str,
            launch_template_id: str,
            min_size: int,
            max_size: int,
            desired_capacity: int,
            vpc_zone_identifier: str,
            cluster_name: str
    ) -> None:
        """Creates autoscaling group

Args:
    name: launch template name
    launch_template_id: launch template id
    min_size: the minimum size of the group
    max_size: the maximum size of the group
    desired_capacity: initial capacity of autoscaling group at the time of creation
    vpc_zone_identifier: A comma-separated list of subnet IDs for a virtual private cloud (VPC)
    where instances in the Auto Scaling group can be created.
    cluster_name: Name of the EKS cluster
Returns:
    None
"""
        print(f"Creating autoscaling group {name}")
        try:
            self.__autoscaling_client.create_auto_scaling_group(
                AutoScalingGroupName=name,
                LaunchTemplate={
                    'LaunchTemplateId': launch_template_id,
                    'Version': '$Latest'
                },
                MaxSize=max_size,
                MinSize=min_size,
                DesiredCapacity=desired_capacity,
                VPCZoneIdentifier=vpc_zone_identifier,
                Tags=[
                    {
                        'Key': f'kubernetes.io/cluster/{cluster_name}',
                        'Value': 'owned',
                        'PropagateAtLaunch': True
                    }
                ]
            )
            print(f"Created autoscaling group {name}")
        except botocore.exceptions.ClientError as e:
            print(f"Error creating autoscaling group: {str(e)}")
            raise


def authorize_security_group_ingress_egress(
        aws_manager: AwsHypervisorManager,
        cluster_security_group_id: str,
        node_security_group_id: str,
        jumpbox_security_group_id: str
) -> None:
    """Authorizes ingress/egress between cluster plane and worker nodes

    Args:
        aws_manager: AWS hypervisor manager
        cluster_security_group_id: group ID of cluster security group
        node_security_group_id: group ID of node security group
    Returns:
      None
"""
    print("Authorizing security group ingress/egress")
    try:
        # Authorize egress for cluster security group
        ip_permissions: List[dict] = [
            AwsHypervisorManager.get_security_group_ip_permission(
                description="Outbound traffic to worker nodes",
                from_port=1025,
                to_port=65535,
                security_group_id=node_security_group_id,
                ip_protocol="tcp"
            )
        ]
        aws_manager.authorize_security_group_egress(
            group_id=cluster_security_group_id, ip_permissions=ip_permissions
        )

        # Authorize ingress for cluster security group
        ip_permissions = [
            AwsHypervisorManager.get_security_group_ip_permission(
                description="Inbound traffic from worker nodes",
                from_port=443,
                to_port=443,
                security_group_id=node_security_group_id,
                ip_protocol="tcp"
            )
        ]
        aws_manager.authorize_security_group_ingress(
            group_id=cluster_security_group_id, ip_permissions=ip_permissions
        )

        # Authorize ingress for jumpbox security group
        ip_permissions = [
            AwsHypervisorManager.get_security_group_ip_permission(
                description="Inbound traffic from jump box",
                security_group_id=jumpbox_security_group_id,
                ip_protocol="-1"  # it is set to -1 to allow all the ip protocol
            )
        ]
        aws_manager.authorize_security_group_ingress(
            group_id=cluster_security_group_id, ip_permissions=ip_permissions
        )

        # Setup ingress for node security group
        ip_permissions = [
            AwsHypervisorManager.get_security_group_ip_permission(
                description="Inbound traffic from worker nodes",
                security_group_id=node_security_group_id,
                ip_protocol="-1"  # it is set to -1 to allow all the ip protocol
            ),
            AwsHypervisorManager.get_security_group_ip_permission(
                description="Inbound traffic from cluster control plane",
                from_port=443,
                to_port=443,
                security_group_id=cluster_security_group_id,
                ip_protocol="tcp"
            ),
            AwsHypervisorManager.get_security_group_ip_permission(
                description="Inbound traffic from cluster control plane",
                from_port=1025,
                to_port=65535,
                security_group_id=cluster_security_group_id,
                ip_protocol="tcp"
            ),
        ]
        aws_manager.authorize_security_group_ingress(
            group_id=node_security_group_id, ip_permissions=ip_permissions
        )
        print("Authorized security group ingress/egress successfully")
    except Exception as e:
        print(f"Error authorizing security group ingress/egress: {str(e)}")
        raise


def setup_security_groups(
        aws_manager: AwsHypervisorManager,
        vpc_id: str,
        prefix: str,
        jumpbox_security_group_id: str
) -> (str, str):
    """Setup security groups for cluster and worker

    Args:
        aws_manager: AWS hypervisor manager
        vpc_id: VPC ID for exocompute cluster
        prefix: prefix for security group names
    Returns:
        cluster_security_group_id, node_security_group_id
    """
    print("Setting up security groups")
    try:
        cluster_group_id = aws_manager.create_security_group(
            name=prefix + "-cluster-security-group",
            description="Security group for EKS cluster plane",
            vpc_id=vpc_id
        )

        node_group_id = aws_manager.create_security_group(
            name=prefix + "-node-security-group",
            description="Security group for EKS worker nodes",
            vpc_id=vpc_id
        )

        authorize_security_group_ingress_egress(
            aws_manager=aws_manager,
            cluster_security_group_id=cluster_group_id,
            node_security_group_id=node_group_id,
            jumpbox_security_group_id=jumpbox_security_group_id,
        )
        return cluster_group_id, node_group_id
    except Exception as e:
        print(f"Error setting up security groups: {str(e)}")
        raise


def create_eks_cluster(
        aws_manager: AwsHypervisorManager,
        security_group_id: str,
        subnet_ids: List[str],
        prefix: str,
        version: str,
        role_arn: str,
        cluster_private_endpoint_enabled: bool,
        restrict_cluster_public_endpoint_access: bool
) -> (str, str, str, str):
    """Creates EKS clusters

    Args:
        aws_manager: AWS hypervisor manager
        security_group_id: security group for cluster
        subnet_ids: prefix for security group names
        prefix: prefix for resources.
        version: kubernetes version
        role_arn: cluster role ARN
        cluster_private_endpoint_enabled: enable private endpoint for the cluster
        restrict_cluster_public_endpoint_access: flag to restrict public endpoint access
    Returns:
        EKS cluster name, EKS cluster ARN, EKS cluster endpoint, cluster certificate authority
"""
    try:
        public_access_cidrs = [PUBLIC_INTERNET_CIDR]
        if cluster_private_endpoint_enabled:
            public_access_cidrs = []
        elif restrict_cluster_public_endpoint_access:
            cluster_private_endpoint_enabled = True
            for ip in RSC_DEPLOYMENT_IPS:
                public_access_cidrs.append(ip + "/32")

        return aws_manager.create_cluster(
            name=prefix + "-eks-cluster",
            version=version,
            role_arn=role_arn,
            subnet_ids=subnet_ids,
            cluster_security_group_id=security_group_id,
            cluster_private_endpoint_enabled=cluster_private_endpoint_enabled,
            public_access_cidrs=public_access_cidrs,
        )
    except Exception as e:
        print(f"Error creating EKS cluster: {str(e)}")
        raise


def get_default_domain_name(region: str) -> str:
    """
GetDefaultDomainName returns the default domain name that is used as the suffix in the hostname.
For us-east-1 region, it returns compute.internal. For all other regions, it returns <region>.compute.internal.
https://docs.aws.amazon.com/vpc/latest/userguide/vpc-dns.html#vpc-dns-hostnames

    Args:
        region: AWS region
    Returns:
        domain name
"""
    if region == "us-east-1":
        return "compute.internal"
    return f"{region}.compute.internal"


def get_user_data(
        cluster_name: str,
        certificate_authority: str,
        cluster_endpoint: str,
        domain_name: str,
        is_network_proxy_supported: bool = False,
        is_imdsv2_supported: bool = True
) -> str:
    """User data for launch template

    Args:
    Returns:
        returns user_data string
"""
    user_data_str = USER_DATA_FORMAT % (
        domain_name, cluster_name, certificate_authority, cluster_endpoint
    )

    if is_network_proxy_supported:
        metadata_api_request = metadata_api_request_without_token
        if is_imdsv2_supported:
            metadata_api_request = metadata_api_request_with_token

        user_data_str = USER_DATA_NW_PROXY_FORMAT.format(
            "",  # HTTP Proxy
            "",  # HTTPS Proxy
            "",  # No Proxy
            metadata_api_request,
            user_data_str
        )

    user_data_bytes = user_data_str.encode("ascii")
    base64_bytes = base64.b64encode(user_data_bytes)
    base64_string = base64_bytes.decode("ascii")
    return base64_string


def setup_launch_template(
        aws_manager: AwsHypervisorManager,
        cluster_name: str,
        certificate_authority: str,
        cluster_endpoint: str,
        region: str,
        prefix: str,
        instance_profile_arn: str,
        worker_node_security_group: str,
        node_type: str
) -> str:
    """Setup launch template for woker nodes

    Args:
    Returns:
        returns launch template ID
    """

    try:
        print("Setting up launch template")
        user_data = get_user_data(
            cluster_name=cluster_name,
            cluster_endpoint=cluster_endpoint,
            certificate_authority=certificate_authority,
            domain_name=get_default_domain_name(region)
        )

        block_device_mappings = [{
            'DeviceName': '/dev/sdb',
            'Ebs': {
                'DeleteOnTermination': True,
                'VolumeSize': 60,
                'VolumeType': 'gp3',
            },
        }]

        instance_metadata_options = {
            'HttpTokens': 'required',
            'HttpPutResponseHopLimit': 2,
        }

        return aws_manager.create_launch_template(
            name=prefix + "-launch-template",
            block_device_mappings=block_device_mappings,
            ami_id=aws_manager.get_eks_node_ami(EKSK8s_VERSION),
            node_type=node_type,
            user_data=user_data,
            instance_profile_arn=instance_profile_arn,
            instance_metadata_options=instance_metadata_options,
            security_group=worker_node_security_group,
        )
    except Exception as e:
        print(f"Error setting up launch template: {str(e)}")
        raise


def strip_paths_from_arn(arn: str) -> str:
    """Strip paths from ARN

    Args:
    Returns:
        returns ARN without paths
    """
    try:
        parsed_arn = arnparse.arnparse(arn)
        resource_parts = str.split(parsed_arn.resource, "/")
        if len(resource_parts) <= 0:
            raise Exception("Invalid ARN")

        # While constructing the aws-auth configmap, the master/worker node role ARN
        # should not include paths.
        # (Ref: https://docs.aws.amazon.com/eks/latest/userguide/add-user-role.html)
        role_without_path = resource_parts[-1]
        arn_without_path = (
            f"{ARN_PREFIX}{parsed_arn.partition}{ARN_DELIMITER}"
            f"{parsed_arn.service}{ARN_DELIMITER}{ARN_DELIMITER}"
            f"{parsed_arn.account_id}{ARN_DELIMITER}{parsed_arn.resource_type}/"
            f"{role_without_path}"
        )
        return arn_without_path
    except Exception as e:
        print(f"Error stripping paths from ARN: {str(e)}")
        raise


def persist_kubectl_configuration(
        cluster_endpoint: str,
        cluster_certificate_authority: str,
        cluster_name: str,
        cluster_arn: str
) -> str:
    """Persist kubectl configuration to a file for kubectl commands.

    Args:
        cluster_endpoint: cluster endpoint
        cluster_certificate_authority: cluster certificate authority
        cluster_name: cluster name
        cluster_arn: cluster ARN
    Returns:
        returns cluster config file path
    """
    try:
        cluster_config = {
            "apiVersion":
                "v1",
            "kind":
                "Config",
            "clusters": [{
                "cluster": {
                    "server":
                        str(cluster_endpoint),
                    "certificate-authority-data":
                        str(cluster_certificate_authority)
                },
                "name": cluster_arn
            }],
            "contexts": [{
                "context": {
                    "cluster": cluster_arn,
                    "user": cluster_arn,
                },
                "name": cluster_arn
            }],
            "current-context":
                cluster_arn,
            "preferences": {},
            "users": [{
                "name": cluster_arn,
                "user": {
                    "exec": {
                        "apiVersion": "client.authentication.k8s.io/v1alpha1",
                        "command": "aws-iam-authenticator",
                        "args": ["token", "-i", cluster_name]
                    }
                }
            }]
        }

        config_text = yaml.dump(cluster_config, default_flow_style=False)

        # Determine the path for the kubectl config file
        kube_dir = expanduser("~") + "/.kube"
        config_file = kube_dir + "/config"

        # Ensure the .kube directory exists
        if not os.path.exists(kube_dir):
            print(f"Directory {kube_dir} does not exist. Creating it.")
            os.makedirs(kube_dir)

        print("Writing kubectl configuration to ", config_file)
        with open(config_file, "w") as file:
            file.write(config_text)
        print("Done: Written kubectl configuration to ", config_file)
        return config_file
    except Exception as e:
        print(f"Error persisting kubectl configuration: {str(e)}")
        raise


def get_config_map(
        worker_node_role_arn: str, cross_account_role_arn: str
) -> client.V1ConfigMap:
    """Setup config map for connecting worker nodes to EKS cluster

        Args:
        Returns:
            returns config map
    """
    try:
        worker_node_role_arn_without_path = strip_paths_from_arn(
            worker_node_role_arn
        )
        cross_account_role_arn_without_path = strip_paths_from_arn(
            cross_account_role_arn
        )

        config_map = client.V1ConfigMap(
            api_version="v1",
            kind="ConfigMap",
            metadata=client.V1ObjectMeta(
                name=CONFIG_MAP_NAME,
                namespace=KUBE_SYSTEM_NAMESPACE,
            ),
            data={
                MAP_ROLES_DATA_KEY:
                    MAP_ROLE_DATA_FORMAT % (
                        worker_node_role_arn_without_path,
                        cross_account_role_arn_without_path,
                    ),
            },
        )
        return config_map
    except Exception as e:
        print(f"Error getting config map: {str(e)}")
        raise


def connect_worker_nodes_to_cluster(
        worker_node_role_arn: str,
        cross_account_role_arn: str,
        cluster_endpoint: str,
        cluster_certificate_authority: str,
        cluster_name: str,
        cluster_arn: str
) -> None:
    """Connect worker nodes to EKS cluster.

    As part of this we create a config map in kube-system namespace with the
    worker node role ARN and cross account role ARN. This config map is used by
    the aws-auth controller to map the IAM roles to Kubernetes users and groups.

        Args:
            worker_node_role_arn: worker node role ARN
            cross_account_role_arn: cross account role ARN
            cluster_endpoint: cluster endpoint
            cluster_certificate_authority: cluster certificate authority
            cluster_name: cluster name
            cluster_arn: cluster ARN
        Returns:
            None
    """
    try:
        config_path = persist_kubectl_configuration(
            cluster_endpoint,
            cluster_certificate_authority,
            cluster_name,
            cluster_arn
        )

        config.load_kube_config(config_file=config_path)
        v1 = client.CoreV1Api()

        config_map = get_config_map(
            worker_node_role_arn=worker_node_role_arn,
            cross_account_role_arn=cross_account_role_arn
        )

        print("Submitting request to create config map")
        v1.create_namespaced_config_map(
            namespace=KUBE_SYSTEM_NAMESPACE, body=config_map
        )
        print("Done: Config map created successfully")
    except Exception as e:
        print(f"Error connecting worker nodes to cluster: {str(e)}")
        raise


def setup_customer_exocompute(
        aws_access_key: str,
        aws_secret_key: str,
        aws_session_id: str,
        aws_region: str,
        vpc_id: str,
        jumpbox_security_group_id: str,
        subnet_ids: List[str],
        prefix: str,
        master_role_arn: str,
        worker_node_role_arn: str,
        worker_node_instance_profile_arn: str,
        cross_account_role: str,
        node_type: str = NODE_TYPE
) -> str:
    """Setup security groups for cluster and worker

        Args:
        Returns:
            EKS cluster ARN
    """
    '''
    If private endpoint access is enabled, then K8s API access from worker
    nodes stays within customer's VPC. Note that it doesn't disable public
    access, cluster remains accessible from public internet as well.

    https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html
    '''
    cluster_private_endpoint_enabled = True
    '''
    If restrict public endpoint access is enabled, then K8s API server public
    endpoint access is restricted to Polaris deployment and Bastion CIDRs.
    If disabled, the endpoint remains accessible to the public internet(0.0.0.0/0).
    If enabled, we enforce the cluster private endpoint access to true, otherwise there
    will be no way for the worker nodes to communicate to the API server.
    '''
    restrict_cluster_public_endpoint_access = False

    try:
        print("Starting setup for customer exocompute")

        aws_manager = AwsHypervisorManager(
            access_key_id=aws_access_key,
            secret_key_id=aws_secret_key,
            session_token=aws_session_id,
            region=aws_region
        )

        # 1. Setup security_groups
        cluster_security_group_id, node_security_group_id = setup_security_groups(
            aws_manager=aws_manager,
            vpc_id=vpc_id,
            prefix=prefix,
            jumpbox_security_group_id=jumpbox_security_group_id
        )

        # 2. Create EKS Cluster
        cluster_name, cluster_arn, cluster_endpoint, cluster_certificate_authority = create_eks_cluster(
            aws_manager=aws_manager,
            security_group_id=cluster_security_group_id,
            subnet_ids=subnet_ids,
            prefix=prefix,
            version=EKSK8s_VERSION,
            role_arn=master_role_arn,
            cluster_private_endpoint_enabled=cluster_private_endpoint_enabled,
            restrict_cluster_public_endpoint_access=restrict_cluster_public_endpoint_access,
        )

        # 3. Setup launch template
        launch_template_id = setup_launch_template(
            aws_manager=aws_manager,
            cluster_name=cluster_name,
            certificate_authority=cluster_certificate_authority,
            cluster_endpoint=cluster_endpoint,
            region=aws_region,
            prefix=prefix,
            instance_profile_arn=worker_node_instance_profile_arn,
            worker_node_security_group=node_security_group_id,
            node_type=node_type
        )

        # 4. Create Auto Scaling group
        aws_manager.create_autoscaling_group(
            name=prefix + "-autoscaling-group",
            launch_template_id=launch_template_id,
            min_size=1,
            max_size=64,
            desired_capacity=1,
            vpc_zone_identifier=",".join(subnet_ids),
            cluster_name=cluster_name
        )

        # 5. Connect Worker nodes to EKS cluster
        connect_worker_nodes_to_cluster(
            worker_node_role_arn=worker_node_role_arn,
            cross_account_role_arn=cross_account_role,
            cluster_endpoint=cluster_endpoint,
            cluster_certificate_authority=cluster_certificate_authority,
            cluster_name=cluster_name,
            cluster_arn=cluster_arn
        )

        print("Completed setup for customer exocompute")
        return str(cluster_arn)
    except Exception as e:
        print(f"Error setting up customer exocompute: {str(e)}")
        raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Setup Customer Exocompute')
    parser.add_argument(
        '--aws-access-key', required=True, help='AWS Access Key'
    )
    parser.add_argument(
        '--aws-secret-key', required=True, help='AWS Secret Key'
    )
    parser.add_argument(
        '--aws-session-id', required=True, help='AWS Session ID'
    )
    parser.add_argument('--aws-region', required=True, help='AWS Region')
    parser.add_argument('--vpc-id', required=True, help='VPC ID')
    parser.add_argument(
        '--jumpbox-security-group-id',
        required=True,
        help='Jumpbox Security Group ID'
    )
    parser.add_argument(
        '--subnet-ids', required=True, nargs='+', help='Subnet IDs'
    )
    parser.add_argument('--prefix', required=True, help='Prefix')
    parser.add_argument(
        '--master-role-arn', required=True, help='Master Role ARN'
    )
    parser.add_argument(
        '--worker-node-role-arn', required=True, help='Worker Node Role ARN'
    )
    parser.add_argument(
        '--worker-node-instance-profile-arn',
        required=True,
        help='Worker Node Instance Profile ARN'
    )
    parser.add_argument(
        '--cross-account-role', required=True, help='Cross Account Role ARN'
    )
    parser.add_argument('--node-type', default=NODE_TYPE, help='Node Type')

    args = parser.parse_args()

    setup_customer_exocompute(
        aws_access_key=args.aws_access_key,
        aws_secret_key=args.aws_secret_key,
        aws_session_id=args.aws_session_id,
        aws_region=args.aws_region,
        vpc_id=args.vpc_id,
        jumpbox_security_group_id=args.jumpbox_security_group_id,
        subnet_ids=args.subnet_ids,
        prefix=args.prefix,
        master_role_arn=args.master_role_arn,
        worker_node_role_arn=args.worker_node_role_arn,
        worker_node_instance_profile_arn=args.worker_node_instance_profile_arn,
        cross_account_role=args.cross_account_role,
        node_type=args.node_type
    )
