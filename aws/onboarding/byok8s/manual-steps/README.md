# Documentation for Manually Creating an EKS Cluster for RSC Exocompute

This documentation outlines the steps to manually create an EKS cluster and associated resources on AWS, similar to the given Python script.

## Prerequisites:
1. AWS CLI configured with necessary permissions.
2. IAM Role with required policies.
    - **Example ARN values** used to describe the steps below: `master-node-role-arn`, `worker-node-role-arn`, `cross-account-role-arn`, `worker-node-instance-profile-arn`
3. Amazon VPC with subnets.
    - **Example VPC** used to describe the steps below: `vpc-0123456789abcdef0`. **NOTE** VPC should be consistent in all the steps.
    - **Example subnets** used to describe the steps below: `subnet-0123456789abcdef0`, `subnet-0123456789abcdef1`. **NOTE** subnets used under above VPC should be consistent in all the steps.

## Steps:

### 1. Setup Security Groups

#### a. Create Security Group for EKS Cluster

1. **Open the Amazon** [VPC console](https://console.aws.amazon.com/vpc/) and choose `Security Groups`.
2. **Create the security group with the following details**:
    - **Name tag**: Enter your desired security group name (e.g., `rubrik-cluster-security-group`)
    - **Description**: `Security group for EKS cluster plane`
    - **VPC**: Select your desired VPC (e.g., `vpc-0123456789abcdef0`)
3. Click on **Create security group**.

#### b. Create Security Group for Worker Nodes

1. **Similar to above, create another security group with the following details**:
    - **Name tag**: Enter your desired security group name (e.g., `rubrik-node-security-group`)
    - **Description**: `Security group for EKS worker nodes`
    - **VPC**: Select your desired VPC (e.g., `vpc-0123456789abcdef0`)

#### c. Authorize Security Group Ingress and Egress

1. **Edit inbound rules for** `rubrik-cluster-security-group` and save.
    - **Add the following rule**:
        - **Type**: HTTPS
        - **Protocol**: TCP (Prefilled)
        - **Port range**: 443 (Prefilled)
        - **Source**: Custom, `rubrik-node-security-group` (Replace with actual Node Security Group ID created above from dropdown)
        - **Description**: Inbound traffic from worker nodes
2. **Edit outbound rules for** `rubrik-cluster-security-group` and save.
    - **Add the following rule**:
        - **Type**: Custom TCP
        - **Protocol**: TCP (Prefilled)
        - **Port range**: `1025 - 65535`
        - **Source**: Custom, `rubrik-node-security-group` (Replace with actual Node Security Group ID created above from dropdown)
        - **Description**: Outbound traffic to worker nodes
3. **Edit inbound rules for** `rubrik-node-security-group` and save.
    - **Add the following rule**:
        - **Type**: All traffic
        - **Protocol**: All (Prefilled)
        - **Port range**: All (Prefilled)
        - **Source**: Custom, `rubrik-node-security-group` (Replace with actual Node Security Group ID created above from dropdown)
        - **Description**: Inbound traffic from worker nodes
    - **Add the following rule**:
        - **Type**: Custom TCP
        - **Protocol**: TCP (Prefilled)
        - **Port range**: `1025 - 65535`
        - **Source**: Custom, `rubrik-cluster-security-group` (Replace with actual Cluster Security Group ID created above from dropdown)
        - **Description**: Inbound traffic from cluster control plane
    - **Add the following rule**:
        - **Type**: HTTPS
        - **Protocol**: TCP (Prefilled)
        - **Port range**: 443 (Prefilled)
        - **Source**: Custom, `rubrik-cluster-security-group` (Replace with actual Cluster Security Group ID created above from dropdown)
        - **Description**: Inbound traffic from cluster control plane

### 2. Create EKS Cluster

#### a. Create the EKS Cluster

1. **Open the Amazon** [EKS console](https://console.aws.amazon.com/eks/home) and choose **Add cluster**, then **Create**.
2. **Configure the Cluster** and then next:
    - **Name**: Enter your desired cluster name (e.g., `rubrik-eks-cluster`)
    - **Kubernetes version**: `1.31`
    - **Cluster Service Role**: Select the IAM role (e.g., `master-node-role-arn`) under the cluster service role.
    - **Cluster access**: ConfigMap
3. **Specify networking** and then next:
    - **VPC**: Select your VPC (e.g., `vpc-0123456789abcdef0`)
    - **Subnet IDs**: Select the subnets under the VPC (e.g., `subnet-0123456789abcdef0`, `subnet-0123456789abcdef1`)
    - **Security Group**: Select your cluster security group (e.g., `rubrik-cluster-security-group`)
    - **Cluster IP address family**: IPv4
    - **Cluster endpoint access**: Private
4. **Control plane logging** (can be left as default) and then next:
5. **Select add-ons** and then next:
    - CoreDNS
    - kube-proxy
    - Amazon VPC CNI
    - Amazon EKS Pod Identity Agent (Optional)
6. Click on **Create** and **Wait** for the cluster and add-ons status to change to `ACTIVE`.

### 3. Setup Launch Template

#### a. Create Launch Template

1. **Open the Amazon** [EC2 console](https://console.aws.amazon.com/ec2/) and choose `Launch Templates`.
2. **Create launch template** with the following details:
    - **Launch template name**: Enter your desired template name (e.g., `rubrik-launch-template`)
    - **AMI ID**: Fetch from SSM parameter (Fetches the AWS recommended EKS worker node AMI ID from [here](https://docs.aws.amazon.com/eks/latest/userguide/eks-optimized-ami.html) e.g., `ami-03d76896f1d3223f2`)
    - **Instance type**: Select your instance type (e.g., `m5.2xlarge`)
    - **Security groups**: Choose your node security group (e.g., `rubrik-node-security-group`)
    - **Update config under root EBS Volume to**:
        - Size (GiB): 60
        - Volume type: gp3
    - **Advanced details**:
        - IAM instance profile: `worker-node-instance-profile-arn` (Replace with the exact ARN value)
        - Metadata version: V2 only (token required)
        - Metadata response hop limit: 2
    - **User data**: Copy the user data content from the script after replacing the following placeholders:
        - domain-name: For us-east-1 region, domain-name is `compute.internal` and for all other regions, its `<region>.compute.internal` (e.g., `eu-west-1.compute.internal`). Follow the doc for [reference](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-dns.html#vpc-dns-hostnames).
        - eks-cluster-name: Cluster name created above (e.g., `rubrik-eks-cluster`)
        - certificate-authority: Certificate authority of the cluster (`rubrik-eks-cluster`) created above
        - api-server-endpoint: API server endpoint of the cluster (`rubrik-eks-cluster`) created above
          ```bash
          #!/bin/bash
          set -o xtrace
   
          host=$(hostname)
          if [[ ${#host} -gt 63 ]]; then
          hostnamectl set-hostname $(hostname | cut -d "." -f 1).<domain-name>
          fi

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
          /etc/eks/bootstrap.sh <eks-cluster-name> --b64-cluster-ca <certificate-authority> --apiserver-endpoint <api-server-endpoint>
          ```

### 4. Create Auto Scaling Groups (One per Subnet)

#### a. Create Auto Scaling Groups

**Note**: Create one Auto Scaling Group per subnet for better distribution and availability. For the first Auto Scaling Group, set min_size to 1. For subsequent Auto Scaling Groups, set min_size to 0.

1. **Open the Amazon** [EC2 console](https://console.aws.amazon.com/ec2/) and choose `Auto Scaling Groups`.

2. **Create Auto Scaling groups (one per subnet) with the following details**:
    - **Auto Scaling group name**: Enter sequential names for each group (e.g., `rubrik-autoscaling-group-1`, `rubrik-autoscaling-group-2`)
    - **Launch template**: Select your launch template created above (e.g., `rubrik-launch-template (Latest version)`)
    - **VPC**: Select your VPC (e.g., `vpc-0123456789abcdef0`)
    - **Subnets**: Select one subnet per Auto Scaling Group (e.g., `subnet-0123456789abcdef0` for first group, `subnet-0123456789abcdef1` for second group)
    - **Set minimum/maximum size**:
        - **First Auto Scaling Group**: min=1, max=64, desired=1
        - **Second Auto Scaling Groups**: min=0, max=64, desired=1
    - **Add a tag**:
        - Key: kubernetes.io/cluster/\<cluster-name\> (e.g., `kubernetes.io/cluster/rubrik-eks-cluster`)
        - Value: owned
        - **Check** Tag new instances

### 5. Connect Worker Nodes to EKS Cluster

#### a. Configure AWS Auth ConfigMap

1. **Download and Configure kubectl**: Instructions can be found [here](https://docs.aws.amazon.com/eks/latest/userguide/install-kubectl.html).
2. **Update kubeconfig File** by running the following command using AWS CLI:
    - region: Region of cluster (e.g., eu-west-1)
    - name: Name of the cluster (e.g., `rubrik-eks-cluster`)
   ```bash
   aws eks update-kubeconfig --region <region> --name <name>
   ```
3. **Create the aws-auth ConfigMap** 
   - Create the 'aws-auth-cm.yaml' from below yaml after replacing the placeholders(worker-node-role-arn, cross-account-role-arn):
       ```yaml
       apiVersion: v1
       kind: ConfigMap
       metadata:
         name: aws-auth
         namespace: kube-system
       data:
         mapRoles: |
           - rolearn: <worker-node-role-arn>
             username: system:node:{{EC2PrivateDNSName}}
             groups:
               - system:bootstrappers
               - system:nodes
           - rolearn: <cross-account-role-arn>
             username: rubrik
             groups:
               - system:masters
       ```
      - **Apply ConfigMap by running the following command**:
       ```bash
       kubectl apply -f aws-auth-cm.yaml
       ```

### Conclusion

You may also refer to the AWS EKS [documentation](https://docs.aws.amazon.com/eks/index.html) or seek assistance from Rubrik support.
