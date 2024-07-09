# Steps to execute EKS cluster setup script

This README provides detailed instructions to run the script (rubrik_create_private_eks_cluster.py) using AWS keys and other necessary configurations. __The Kubernetes version used to setup EKS cluster in this script is `1.29`.__

## Prerequisites

### Jumpbox Specifications

The jumpbox is an EC2 instance behind the same VPC, subnet, and security group on which the EKS cluster is launched. It serves as a secure point for accessing the EKS cluster.

**Note:** The commands below are intended for a Linux EC2 instance. If you are running this script on a different type of EC2 instance, follow the same steps but adjust the commands accordingly to match your specific environment.

Ensure you have Python 3.x installed on your jumpbox:

## Setup Instructions

1. **Export AWS Credentials**

    ```sh
    export AWS_ACCESS_KEY_ID="<YOUR_AWS_ACCESS_KEY_ID>"
    export AWS_SECRET_ACCESS_KEY="<YOUR_AWS_SECRET_ACCESS_KEY>"
    export AWS_SESSION_TOKEN="<YOUR_AWS_SESSION_TOKEN>"
    ```

   Export your AWS access keys and token to your environment variables.

2. **Update and Install Dependencies**

    ```sh
    sudo apt update -y
    ```

   Update the list of available packages and their versions.

    ```sh
    sudo apt install -y python3-pip
    ```

   Install pip, the Python package installer.

    ```sh
    sudo apt install -y python3-pip python3-venv
    ```

   Install `venv`, to create isolated Python environments.

3. **Install AWS IAM Authenticator**

   As per the [documentation](https://weaveworks-gitops.awsworkshop.io/60_workshop_6_ml/00_prerequisites.md/50_install_aws_iam_auth.html):

    ```sh
    curl -o aws-iam-authenticator https://amazon-eks.s3.us-west-2.amazonaws.com/1.15.10/2020-02-22/bin/linux/amd64/aws-iam-authenticator
    ```

   Download AWS IAM Authenticator.

    ```sh
    chmod +x ./aws-iam-authenticator
    ```

   Make the downloaded file executable.

    ```sh
    sudo mv ./aws-iam-authenticator /usr/local/bin
    ```

   Move the executable to the `/usr/local/bin` directory.

4. **Setup Python Virtual Environment**

    ```sh
    python3 -m venv myenv && source myenv/bin/activate
    ```

   Create a virtual environment named `myenv` and activate it.

5. **Install Required Python Packages**

    ```sh
    pip install arnparse==0.0.2 boto3==1.34.36 botocore==1.34.36 kubernetes==29.0.0 PyYAML==6.0.1
    ```

   Install necessary Python packages for the script.

## Running the Script

Use the following sample command to run the script:

```sh
python3 rubrik_create_private_eks_cluster.py \
    --aws-access-key <YOUR_AWS_ACCESS_KEY_ID> \
    --aws-secret-key <YOUR_AWS_SECRET_ACCESS_KEY> \
    --aws-session-id <YOUR_AWS_SESSION_TOKEN> \
    --aws-region <YOUR_AWS_REGION> \
    --vpc-id <YOUR_VPC_ID> \
    --jumpbox-security-group-id <YOUR_JUMPBOX_SECURITY_GROUP_ID> \
    --subnet-ids <YOUR_SUBNET_ID_1> <YOUR_SUBNET_ID_2> \
    --prefix <YOUR_PREFIX> \
    --master-role-arn <YOUR_MASTER_ROLE_ARN> \
    --worker-node-role-arn <YOUR_WORKER_NODE_ROLE_ARN> \
    --worker-node-instance-profile-arn <YOUR_WORKER_NODE_INSTANCE_PROFILE_ARN> \
    --cross-account-role <YOUR_CROSS_ACCOUNT_ROLE_ARN>
```

### Parameter Descriptions

-   --aws-access-key: Your AWS Access Key ID.
-   --aws-secret-key: Your AWS Secret Access Key.
-   --aws-session-id: Your AWS Session Token.
-   --aws-region: The AWS region where your resources are located (e.g., eu-west-1).
-   --vpc-id: The ID of the VPC where the EKS cluster will be deployed.
-   --jumpbox-security-group-id: The security group ID for your jumpbox.
-   --subnet-ids: The IDs of the subnets for your EKS cluster (provide multiple subnet IDs separated by space).
-   --prefix: A prefix for naming your resources.
-   --master-role-arn: The ARN of the master node IAM role.
-   --worker-node-role-arn: The ARN of the worker node IAM role.
-   --worker-node-instance-profile-arn: The ARN of the worker node instance profile.
-   --cross-account-role: The ARN of the cross-account role.
-   --node-type: The type of EC2 instance for your worker nodes (e.g., m5.2xlarge).