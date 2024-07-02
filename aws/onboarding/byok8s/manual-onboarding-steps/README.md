# Documentation for Manually Creating an EKS Cluster for RSC exocompute

This documentation outlines the steps to manually create an EKS cluster and associated resources on AWS, similar to the given Python script.

## Prerequisites:
1. AWS CLI configured with necessary permissions.
2. IAM Role with required policies.
   - **Example arn values** used to describe the steps below: `master-node-role-arn`, `worker-node-role-arn`, `cross-account-role`, `worker-node-instance-profile-arn` 
3. Amazon VPC with subnets.
   - **Example vpc** used to describe the steps below: `vpc-0123456789abcdef0`
   - **Example subnet** used to describe the steps below: `subnet-0123456789abcdef0`, `subnet-0123456789abcdef1`

## Steps:

### 1. Setup Security Groups

#### a. Create Security Group for EKS Cluster

1. **Open the Amazon VPC console** [here](https://console.aws.amazon.com/vpc/) and choose `Security Groups`.
2. **Create the security group with the following details**:
   - **Name tag**: Enter your desired security group name (e.g., `rubrik-cluster-security-group`)
   - **Description**: `Security group for EKS cluster plane`
   - **VPC**: Select your desired VPC (e.g., `vpc-0123456789abcdef0`)
3. Click on **Create security group**.

#### b. Create Security Group for Worker Nodes

1. **Similar to above, create another security group with the following details**
   - **Name tag**: Enter your desired security group name (e.g., `rubrik-node-security-group`)
   - **Description**: `Security group for EKS worker nodes`
   - **VPC**: Select your desired VPC (e.g., `vpc-0123456789abcdef0`)

#### c. Authorize Security Group Ingress and Egress

1. **Edit inbound rules for** `rubrik-cluster-security-group`.
   - **Add the following rule** and save:
     - **Type**: HTTPS
     - **Protocol**: TCP (Prefilled)
     - **Port range**: 443(Prefilled)
     - **Source**: Custom, `sg-rubrik-node-security-group` (Replace with actual Node Security Group ID created above from dropdown)
     - **Description**: Inbound traffic from worker nodes
2. **Edit outbound rules for** `rubrik-cluster-security-group`.
   - **Add the following rule** and save:
     - **Type**: Custom TCP
     - **Protocol**: TCP (Prefilled)
     - **Port range**: `1025 - 65535`
     - **Source**: Custom, `sg-rubrik-node-security-group` (Replace with actual Node Security Group ID created above from dropdown)
     - **Description**: Outbound traffic to worker nodes
3. **Edit inbound rules for** `sg-rubrik-node-security-group`.
   - **Add the following rule**:
     - **Type**: All traffic
     - **Protocol**: All (Prefilled)
     - **Port range**: All (Prefilled)
     - **Source**: Custom, `sg-rubrik-node-security-group` (Replace with actual Node Security Group ID created above from dropdown)
     - **Description**: Inbound traffic from worker nodes
   - **Add the following rule**:
     - **Type**: Custom TCP
     - **Protocol**: TCP (Prefilled)
     - **Port range**: `1025 - 65535`
     - **Source**: Custom, `sg-rubrik-cluster-security-group` (Replace with actual Cluster Security Group ID created above from dropdown)
     - **Description**: Inbound traffic from cluster control plane
   - **Add the following rule** and save:
     - **Type**: HTTPS
     - **Protocol**: TCP (Prefilled)
     - **Port range**: 443(Prefilled)
     - **Source**: Custom, `sg-rubrik-cluster-security-group` (Replace with actual Cluster Security Group ID created above from dropdown)
     - **Description**: Inbound traffic from cluster control plane
     
### 2. Create EKS Cluster

#### a. Create the EKS Cluster

1. **Open the Amazon EKS console** [here](https://console.aws.amazon.com/eks/home) and choose **Add cluster**, then **Create**.
2. **Configure the Cluster** and then next:
   - **Name**: Enter your desired cluster name (e.g., `rubrik-eks-cluster`)
   - **Kubernetes version**: `1.29`
   - **Cluster Service Role**: Select the IAM role created for EKS(e.g., `master-node-role-arn`).
   - **Cluster access**: ConfigMap
3. **Specify networking** and then next:
  - **VPC**: Select your VPC (e.g., `vpc-0123456789abcdef0`)
  - **Subnet IDs**: Select the subnets under the vpc (e.g., `subnet-0123456789abcdef0`, `subnet-0123456789abcdef1`)
  - **Security Group**: Select your cluster security group (e.g., `sg-rubrik-cluster-security-group`)
  - **Cluster IP address family**: IPv4
  - **Cluster endpoint access**: Private
4. **Control plane logging** (can be left as default) and then next:
5. **Select add-ons**  and then next:
   - CoreDNS
   - kube-proxy
   - Amazon VPC CNI
   - Amazon EKS Pod Identity Agent (Optional)
6. Click on **Create** and **Wait** for the cluster and addons status to change to `ACTIVE`.

### 3. Setup Launch Template

#### a. Create Launch Template

1. **Open the Amazon EC2 console** at https://console.aws.amazon.com/ec2/.
2. **In the navigation pane**, choose `Launch Templates`.
3. **Choose Create launch template**.
4. **Enter the following details**:
   - **Launch template name**: Enter your desired template name (e.g., `rubrik-launch-template`)
   - **AMI ID**: Fetch from SSM parameter (e.g., `ami-0123456789abcdef0`)
   - **Instance type**: Select your instance type (e.g., `m5.2xlarge`)
   - **Key pair**: Select your existing key pair if SSH access is required.
   - **Security groups**: Choose your node security group (e.g., `sg-rubrik-node-security-group`)
   - **User data**: Copy the user data content from the script.

5. **Choose Create launch template**.

### 4. Create Auto Scaling Group

#### a. Create Auto Scaling Group

1. **Open the Amazon EC2 console** at https://console.aws.amazon.com/ec2/.
2. **In the navigation pane**, choose `Auto Scaling Groups`.
3. **Choose Create Auto Scaling group**.
4. **Enter the following details**:
   - **Auto Scaling group name**: Enter your desired group name (e.g., `rubrik-autoscaling-group`)
   - **Launch template**: Select your launch template (e.g., `rubrik-launch-template (Latest version)`)
   - **VPC**: Select your VPC (e.g., `vpc-0123456789abcdef0`)
   - **Subnets**: Select your subnets (e.g., `subnet-0123456789abcdef0`, `subnet-0123456789abcdef1`)
   - **Set minimum/maximum size**: e.g., min=1, max=3, desired=1.

5. **Choose Create Auto Scaling group**.

### 5. Connect Worker Nodes to EKS Cluster

#### a. Configure AWS Auth ConfigMap

1. **Download and Configure kubectl**: Instructions can be found [here](https://docs.aws.amazon.com/eks/latest/userguide/install-kubectl.html).
2. **Update kubeconfig File**:
    ```bash
    aws eks update-kubeconfig --region us-west-2 --name rubrik-eks-cluster
    ```

3. **Create the aws-auth ConfigMap**:
    ```yaml
    apiVersion: v1
    kind: ConfigMap
    metadata:
      name: aws-auth
      namespace: kube-system
    data:
      mapRoles: |
        - rolearn: arn:aws:iam::123456789012:role/eksNodegroupRole
          username: system:node:{{EC2PrivateDNSName}}
          groups:
            - system:bootstrappers
            - system:nodes
        - rolearn: arn:aws:iam::123456789012:role/rubrik
          username: rubrik
          groups:
            - system:masters
    ```
   - **Apply ConfigMap**:
    ```bash
    kubectl apply -f aws-auth-cm.yaml
    ```

### Conclusion

By following these steps, you have successfully created an EKS cluster and configured the necessary resources manually.

If you have any issues, refer to the AWS EKS [documentation](https://docs.aws.amazon.com/eks/index.html) or seek assistance from AWS support.