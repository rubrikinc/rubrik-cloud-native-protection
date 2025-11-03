# Documentation for Manually Creating an AKS Cluster for RSC Exocompute
This documentation outlines the steps to manually create an AKS cluster and associated resources on Azure to be used as an exocompute cluster with RSC

## Prerequisites:
1. Azure CLI configured with necessary permissions.
   Ensure this by executing the below command and selecting the right subscription.
   ```
   az login
   ```
3. Azure App Id and secret used to onboard exocompute feature in RSC via non-oauth flow.
## Variables:
1. RESOURCE_GROUP - This should be same as the resource group used to onboard exocompute as the permissions are taken at resource group level.
2. VNET_NAME - The name of VNET where the AKS cluster is to be created. This VNET should meet all the network pre-requisites needed for exocompute clusters.
3. AKS_SUBNET_NAME - Subnet to be used for the AKS cluster.
4. VNET_RESOURCE_GROUP - resource group of the VNET where the cluster is created.
5. SP_APP_ID - App Id used to onboard subscription for exocompute feature via non-Oauth flow in RSC.
6. SP_PASSWORD - Client secret used while onboarding subscription for exocompute via non-Oauth flow in RSC.
7. CLUSTER_NAME - Desired name of the BYOK cluster.
8. LOCATION - Azure region where the cluster is to be created.
   
## Create Private AKS Cluster:
Following are configuration we expect for the cluster.

 - Starting node count with min-count of 1 and max-count of 64.
 - Cluster autoscalar enabled.
 - Nodepool-name : `rubrikcloud`
 - Node VM size: `Standard_E8s_v5` (this can be changed as per the workload that  
   needs to be supported).
 - Private Cluster: Enabled
 - Service Principal: App ID used in the exocompute onboarding step
 - Client secret: App secret obtained in exocompute onboarding step
 - Kubernetes Version: `1.31`
 - Only Local authentication mode is supported from RSC, we don't support Microsoft AAD based auth mechanisms for the cluster. The cluster is by default created with local auth mode.
 - Network Plugin to be used: `Azure (Azure CNI)`
 - Network Plugin mode: `Overlay`
 - Ensure that the Vnet and subnet configuration support the above settings.
 - Generate SSH key option is set to true. This ensures that ssh is automatically created if not present at the default location (`~/.ssh/id_rsa` and `~/.ssh/id_rsa.pub`). This public key will be added to the VMs/nodes created by AKS. This is needed to troubleshoot by logging into the nodes if some issues are encountered.

## Example Cluster Creation command:

```
az aks create \
  --resource-group $RESOURCE_GROUP \
  --name $CLUSTER_NAME \
  --location $LOCATION \
  --node-count 1 \
  --nodepool-name rubrikcloud \
  --node-vm-size Standard_E8s_v5 \
  --enable-private-cluster \
  --service-principal $SP_APP_ID \
  --client-secret $SP_PASSWORD \
  --network-plugin azure \
  --network-plugin-mode overlay \
  --vnet-subnet-id $(az network vnet subnet show --resource-group $VNET_RESOURCE_GROUP --vnet-name $VNET_NAME --name $AKS_SUBNET_NAME --query id -o tsv) \
  --kubernetes-version 1.29 \
  --generate-ssh-keys \
  --enable-cluster-autoscaler \
  --min-count 1 \
  --max-count 64
```

## To invoke Run command on private cluster:

```
az aks command invoke \
  --resource-group $RESOURCE_GROUP \
  --name $CLUSTER_NAME \
  --command "kubectl get nodes"
```
