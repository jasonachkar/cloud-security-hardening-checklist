# Azure Security Hardening Checklist

## Overview

This checklist provides comprehensive security hardening controls for Microsoft Azure environments, aligned with CIS Microsoft Azure Foundations Benchmark v2.0.0. Each control includes verification methods, remediation guidance, and risk context.

## Control Format

Each control follows this structure:
- **Control ID**: Unique identifier (e.g., AZ-IAM-01)
- **CIS Reference**: CIS Benchmark control number
- **CIS Level**: 1 (foundational) or 2 (defense-in-depth)
- **Description**: What the control does
- **Security Impact**: Why this matters
- **Verification**: How to check manually
- **Automated Check**: Script reference
- **Remediation**: How to fix
- **Risk if Not Implemented**: Consequences of non-compliance

---

## Identity & Access Management (IAM)

### AZ-IAM-01: Multi-Factor Authentication for Privileged Accounts

**CIS Reference**: 1.1.1, 1.1.2, 1.2.1
**CIS Level**: 1

**Description**: Multi-factor authentication (MFA) must be enabled for all privileged and administrative accounts in Microsoft Entra ID (formerly Azure AD).

**Security Impact**: MFA prevents account takeover from compromised credentials. Privileged accounts have elevated permissions that could compromise the entire Azure environment if stolen.

**Verification (Manual)**:
1. Navigate to Microsoft Entra ID > Users
2. Select each privileged user
3. Review Authentication Methods
4. Verify MFA is registered and enforced

**Automated Check**: `scripts/azure/check-iam.ps1` (Function: Check-MFAStatus)

**Remediation**:
```powershell
# Enable MFA via Conditional Access
# 1. Navigate to Entra ID > Security > Conditional Access
# 2. Create new policy: "Require MFA for Admins"
# 3. Assignments > Users: Select all admin roles
# 4. Access controls > Grant > Require multi-factor authentication
# 5. Enable policy

# Or via PowerShell
New-AzureADMSConditionalAccessPolicy -DisplayName "Require MFA for Admins" `
  -State "Enabled" `
  -Conditions $conditions `
  -GrantControls $grantControls
```

**Risk if Not Implemented**:
- Account takeover from phishing or credential theft
- Unauthorized access to entire Azure subscription
- Data breach and resource compromise
- Compliance violations (CIS, SOC 2, ISO 27001)

---

### AZ-IAM-02: No Permanent Global Administrator Assignments

**CIS Reference**: 1.1.3
**CIS Level**: 1

**Description**: No users should have permanent Global Administrator role assignments. Use Privileged Identity Management (PIM) for just-in-time access.

**Security Impact**: Permanent admin rights increase the attack surface and blast radius of compromised accounts. PIM provides time-limited, approval-based access.

**Verification (Manual)**:
1. Navigate to Entra ID > Roles and administrators
2. Select "Global Administrator"
3. Review assignments
4. Verify all are "Eligible" (PIM) not "Active" (permanent)

**Automated Check**: `scripts/azure/check-iam.ps1` (Function: Check-PermanentGlobalAdmins)

**Remediation**:
```powershell
# Enable PIM and convert permanent to eligible assignments
# 1. Navigate to Privileged Identity Management
# 2. Select Azure AD roles
# 3. For each permanent Global Admin:
#    - Remove permanent assignment
#    - Add eligible assignment
#    - Set maximum duration (e.g., 8 hours)
#    - Require approval and justification
```

**Risk if Not Implemented**:
- Excessive standing privileges
- Inability to audit privileged actions
- Compromised admin accounts have immediate full access
- Compliance violations (Zero Trust, least privilege)

---

### AZ-IAM-03: Restrict Guest User Permissions

**CIS Reference**: 1.5, 1.7, 1.8, 1.9
**CIS Level**: 1

**Description**: Guest users should have limited permissions and should not be able to invite other guests or view directory information.

**Security Impact**: Unrestricted guest access can lead to data exposure and unauthorized external collaboration.

**Verification (Manual)**:
1. Navigate to Entra ID > Users > User settings
2. Check "Guest users permissions are limited" = Yes
3. Check "Members can invite" = No
4. Check "Guests can invite" = No

**Automated Check**: `scripts/azure/check-iam.ps1` (Function: Check-GuestUserSettings)

**Remediation**:
```powershell
# Via Azure Portal
# Entra ID > Users > User settings > External collaboration settings
# Set "Guest user permissions are limited" to Yes
# Set "Members can invite" to No
# Set "Guests can invite" to No

# Via PowerShell
$settings = Get-AzureADDirectorySetting | Where-Object {$_.DisplayName -eq "Group.Unified"}
$settings["AllowGuestsToInviteOthers"] = $false
$settings["AllowMembersToInviteGuests"] = $false
Set-AzureADDirectorySetting -Id $settings.Id -DirectorySetting $settings
```

**Risk if Not Implemented**:
- Unauthorized data access by external users
- Guest users enumerating sensitive directory information
- Uncontrolled external collaboration
- Data exfiltration risk

---

### AZ-IAM-04: Disable Application Registration by Users

**CIS Reference**: 1.4
**CIS Level**: 1

**Description**: Prevent non-admin users from registering applications in Entra ID to control service principal creation.

**Security Impact**: User-created applications can be granted excessive permissions and used as backdoors or for data exfiltration.

**Verification (Manual)**:
1. Navigate to Entra ID > Users > User settings
2. Verify "Users can register applications" = No

**Automated Check**: `scripts/azure/check-iam.ps1` (Function: Check-AppRegistrationSettings)

**Remediation**:
```powershell
# Via Portal: Entra ID > Users > User settings
# Set "Users can register applications" to No

# Via PowerShell
Set-AzureADMSAuthorizationPolicy -AllowUserConsentForRiskyApps $false
```

**Risk if Not Implemented**:
- Shadow IT applications
- Unauthorized service principals with excessive permissions
- OAuth consent phishing attacks
- Data access by unmanaged applications

---

## Logging & Monitoring

### AZ-LOG-01: Activity Log Retention and Export

**CIS Reference**: 5.1.1, 5.1.2
**CIS Level**: 1

**Description**: Activity Logs must be enabled for all subscriptions with retention of 365 days or greater, exported to Log Analytics or Storage Account.

**Security Impact**: Activity Logs provide audit trail for all control plane operations. Retention enables long-term security investigations and compliance.

**Verification (Manual)**:
1. Navigate to Monitor > Activity Log > Export Activity Logs
2. Verify diagnostic settings exist for each subscription
3. Check retention period is ≥ 365 days

**Automated Check**: `scripts/azure/check-logging.ps1` (Function: Check-ActivityLogRetention)

**Remediation**:
```powershell
# Create diagnostic setting for Activity Logs
$subscriptionId = (Get-AzContext).Subscription.Id
$logAnalyticsWorkspaceId = "<workspace-resource-id>"

$setting = @{
    Name = "ActivityLogs-to-LogAnalytics"
    WorkspaceId = $logAnalyticsWorkspaceId
    Enabled = $true
    Category = @(
        "Administrative", "Security", "ServiceHealth", "Alert",
        "Recommendation", "Policy", "Autoscale", "ResourceHealth"
    )
    RetentionEnabled = $true
    RetentionInDays = 365
}

Set-AzDiagnosticSetting @setting -ResourceId "/subscriptions/$subscriptionId"
```

**Risk if Not Implemented**:
- Inability to investigate security incidents
- No audit trail for privileged actions
- Compliance violations (PCI DSS, HIPAA, SOX)
- Limited forensic capabilities

---

### AZ-LOG-02: Microsoft Defender for Cloud Enabled

**CIS Reference**: 2.1.1 - 2.1.16
**CIS Level**: 1 (Servers, App Service), 2 (Others)

**Description**: Microsoft Defender for Cloud must be enabled for all resource types (Servers, App Service, SQL, Storage, Kubernetes, Container Registries, Key Vault).

**Security Impact**: Defender provides threat detection, vulnerability assessment, and security recommendations for cloud workloads.

**Verification (Manual)**:
1. Navigate to Microsoft Defender for Cloud > Environment settings
2. Select subscription
3. Verify Defender plans are enabled for all resource types
4. Check coverage status

**Automated Check**: `scripts/azure/check-logging.ps1` (Function: Check-DefenderForCloud)

**Remediation**:
```powershell
# Enable Defender for Cloud for all resource types
Set-AzSecurityPricing -Name "VirtualMachines" -PricingTier "Standard"
Set-AzSecurityPricing -Name "AppServices" -PricingTier "Standard"
Set-AzSecurityPricing -Name "SqlServers" -PricingTier "Standard"
Set-AzSecurityPricing -Name "StorageAccounts" -PricingTier "Standard"
Set-AzSecurityPricing -Name "KubernetesService" -PricingTier "Standard"
Set-AzSecurityPricing -Name "ContainerRegistry" -PricingTier "Standard"
Set-AzSecurityPricing -Name "KeyVaults" -PricingTier "Standard"

# Enable auto-provisioning of monitoring agent
Set-AzSecurityAutoProvisioningSetting -Name "default" -EnableAutoProvision
```

**Risk if Not Implemented**:
- No threat detection for cloud workloads
- Undetected vulnerabilities and misconfigurations
- Delayed incident response
- Compliance gaps

---

### AZ-LOG-03: Diagnostic Logs for All Resources

**CIS Reference**: 5.1.3
**CIS Level**: 1

**Description**: Diagnostic logs must be enabled for all Azure resources that support logging.

**Security Impact**: Resource-level logs enable detection of data plane attacks and unauthorized access attempts.

**Verification (Manual)**:
1. Navigate to each resource (Storage, SQL, Key Vault, etc.)
2. Select Diagnostic settings
3. Verify logs are enabled and sent to Log Analytics or Storage

**Automated Check**: `scripts/azure/check-logging.ps1` (Function: Check-DiagnosticLogs)

**Remediation**:
```powershell
# Example: Enable diagnostic logs for Storage Account
$storageAccountId = "/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Storage/storageAccounts/{name}"
$workspaceId = "/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.OperationalInsights/workspaces/{name}"

Set-AzDiagnosticSetting -ResourceId $storageAccountId `
  -Name "StorageLogs" `
  -WorkspaceId $workspaceId `
  -Enabled $true `
  -Category "StorageRead", "StorageWrite", "StorageDelete"
```

**Risk if Not Implemented**:
- Blind spots in security monitoring
- Inability to detect data access abuse
- Limited incident investigation capabilities
- Compliance violations

---

### AZ-LOG-04: NSG Flow Logs Enabled

**CIS Reference**: 6.6
**CIS Level**: 2

**Description**: Network Security Group flow logs must be enabled with retention ≥ 90 days for network traffic analysis.

**Security Impact**: NSG flow logs enable detection of lateral movement, data exfiltration, and network-based attacks.

**Verification (Manual)**:
1. Navigate to Network Watcher > NSG flow logs
2. Verify flow logs enabled for all NSGs
3. Check retention period ≥ 90 days

**Automated Check**: `scripts/azure/check-logging.ps1` (Function: Check-NSGFlowLogs)

**Remediation**:
```powershell
# Enable NSG flow logs
$nsg = Get-AzNetworkSecurityGroup -Name "MyNSG" -ResourceGroupName "MyRG"
$storageAccount = Get-AzStorageAccount -Name "flowlogssa" -ResourceGroupName "MyRG"
$networkWatcher = Get-AzNetworkWatcher -Name "NetworkWatcher_eastus" -ResourceGroupName "NetworkWatcherRG"

Set-AzNetworkWatcherFlowLog -NetworkWatcher $networkWatcher `
  -TargetResourceId $nsg.Id `
  -StorageAccountId $storageAccount.Id `
  -EnableFlowLog $true `
  -FormatType Json `
  -FormatVersion 2 `
  -RetentionInDays 90
```

**Risk if Not Implemented**:
- No visibility into network traffic patterns
- Inability to detect lateral movement
- Limited network forensics
- Delayed threat detection

---

## Network Security

### AZ-NET-01: Restrict RDP Access from Internet

**CIS Reference**: 6.1
**CIS Level**: 1

**Description**: RDP (port 3389) must not be accessible from the internet (0.0.0.0/0).

**Security Impact**: Public RDP exposure is a primary attack vector for brute force attacks and exploitation.

**Verification (Manual)**:
1. Navigate to Network Security Groups
2. Review inbound security rules
3. Verify no rules allow port 3389 from 0.0.0.0/0 or internet

**Automated Check**: `scripts/azure/check-network.ps1` (Function: Check-RDPExposure)

**Remediation**:
```powershell
# Remove or modify NSG rules allowing RDP from internet
$nsg = Get-AzNetworkSecurityGroup -Name "MyNSG" -ResourceGroupName "MyRG"

# Option 1: Remove the rule
Remove-AzNetworkSecurityRuleConfig -Name "AllowRDP" -NetworkSecurityGroup $nsg | Set-AzNetworkSecurityGroup

# Option 2: Restrict to specific IP
Set-AzNetworkSecurityRuleConfig -Name "AllowRDP" `
  -NetworkSecurityGroup $nsg `
  -Access Allow `
  -Protocol Tcp `
  -Direction Inbound `
  -Priority 100 `
  -SourceAddressPrefix "YOUR_OFFICE_IP/32" `
  -SourcePortRange "*" `
  -DestinationAddressPrefix "*" `
  -DestinationPortRange 3389 | Set-AzNetworkSecurityGroup

# Recommended: Use Azure Bastion for secure RDP access
```

**Risk if Not Implemented**:
- Brute force attacks against RDP
- Exploitation of RDP vulnerabilities (BlueKeep, etc.)
- Unauthorized VM access
- Ransomware deployment

---

### AZ-NET-02: Restrict SSH Access from Internet

**CIS Reference**: 6.2
**CIS Level**: 1

**Description**: SSH (port 22) must not be accessible from the internet (0.0.0.0/0).

**Security Impact**: Public SSH exposure enables brute force attacks and exploitation of authentication weaknesses.

**Verification (Manual)**:
1. Navigate to Network Security Groups
2. Review inbound security rules
3. Verify no rules allow port 22 from 0.0.0.0/0

**Automated Check**: `scripts/azure/check-network.ps1` (Function: Check-SSHExposure)

**Remediation**:
```powershell
# Restrict SSH access to specific IPs or use Azure Bastion
$nsg = Get-AzNetworkSecurityGroup -Name "MyNSG" -ResourceGroupName "MyRG"

Set-AzNetworkSecurityRuleConfig -Name "AllowSSH" `
  -NetworkSecurityGroup $nsg `
  -Access Allow `
  -Protocol Tcp `
  -Direction Inbound `
  -Priority 100 `
  -SourceAddressPrefix "YOUR_OFFICE_IP/32" `
  -SourcePortRange "*" `
  -DestinationAddressPrefix "*" `
  -DestinationPortRange 22 | Set-AzNetworkSecurityGroup
```

**Risk if Not Implemented**:
- SSH brute force attacks
- Credential stuffing
- Botnet recruitment
- Unauthorized server access

---

### AZ-NET-03: Use Private Endpoints for PaaS Services

**CIS Reference**: Custom (Best Practice)
**CIS Level**: 2

**Description**: Use Private Endpoints for Azure PaaS services (Storage, SQL, Key Vault) to eliminate public internet exposure.

**Security Impact**: Private Endpoints provide private IP addresses for PaaS services, removing them from the public internet and enabling network-level access control.

**Verification (Manual)**:
1. Navigate to each PaaS resource
2. Check Networking > Private endpoint connections
3. Verify private endpoints exist and public access is disabled

**Automated Check**: `scripts/azure/check-network.ps1` (Function: Check-PrivateEndpoints)

**Remediation**:
```powershell
# Create Private Endpoint for Storage Account
$subnet = Get-AzVirtualNetworkSubnetConfig -Name "PrivateEndpointSubnet" -VirtualNetworkName "MyVNet" -ResourceGroupName "MyRG"
$storageAccount = Get-AzStorageAccount -Name "mystorageaccount" -ResourceGroupName "MyRG"

$privateEndpoint = New-AzPrivateEndpoint `
  -ResourceGroupName "MyRG" `
  -Name "storage-private-endpoint" `
  -Location "eastus" `
  -Subnet $subnet `
  -PrivateLinkServiceConnection (New-AzPrivateLinkServiceConnection `
    -Name "storage-connection" `
    -PrivateLinkServiceId $storageAccount.Id `
    -GroupId "blob")

# Disable public network access
Set-AzStorageAccount -ResourceGroupName "MyRG" `
  -Name "mystorageaccount" `
  -PublicNetworkAccess Disabled
```

**Risk if Not Implemented**:
- PaaS services exposed to public internet
- Increased attack surface
- Potential for data exfiltration
- Network-level protection bypassed

---

## Storage Security

### AZ-STORAGE-01: Disable Public Blob Access

**CIS Reference**: 3.2, 3.6
**CIS Level**: 1

**Description**: Public blob access must be disabled at both storage account and container levels to prevent anonymous data access.

**Security Impact**: Public blob access is a leading cause of data breaches in cloud environments.

**Verification (Manual)**:
1. Navigate to Storage Accounts
2. Select each storage account
3. Check Configuration > Allow Blob public access = Disabled
4. Verify no containers have public access level

**Automated Check**: `scripts/azure/check-storage.ps1` (Function: Check-PublicBlobAccess)

**Remediation**:
```powershell
# Disable public blob access at storage account level
Set-AzStorageAccount -ResourceGroupName "MyRG" `
  -Name "mystorageaccount" `
  -AllowBlobPublicAccess $false

# Remove public access from all containers
$ctx = (Get-AzStorageAccount -ResourceGroupName "MyRG" -Name "mystorageaccount").Context
Get-AzStorageContainer -Context $ctx | Set-AzStorageContainerAcl -Permission Off
```

**Risk if Not Implemented**:
- Data breach from publicly accessible blobs
- Unauthorized data download
- Sensitive information exposure
- Compliance violations (GDPR, HIPAA)

---

### AZ-STORAGE-02: Require Secure Transfer (HTTPS)

**CIS Reference**: 3.1
**CIS Level**: 1

**Description**: Storage accounts must require secure transfer (HTTPS/TLS 1.2) to encrypt data in transit.

**Security Impact**: Unencrypted HTTP traffic can be intercepted and read by network attackers (man-in-the-middle).

**Verification (Manual)**:
1. Navigate to Storage Accounts
2. Select each account
3. Check Configuration > Secure transfer required = Enabled
4. Verify Minimum TLS version = Version 1.2

**Automated Check**: `scripts/azure/check-storage.ps1` (Function: Check-SecureTransfer)

**Remediation**:
```powershell
# Enable secure transfer and set minimum TLS version
Set-AzStorageAccount -ResourceGroupName "MyRG" `
  -Name "mystorageaccount" `
  -EnableHttpsTrafficOnly $true `
  -MinimumTlsVersion TLS1_2
```

**Risk if Not Implemented**:
- Data interception during transfer
- Man-in-the-middle attacks
- Credential theft
- Compliance violations

---

### AZ-STORAGE-03: Enable Storage Account Encryption

**CIS Reference**: 3.3, 3.4
**CIS Level**: 1

**Description**: Encryption must be enabled for all storage services (Blob, File, Queue, Table) using Microsoft-managed or customer-managed keys.

**Security Impact**: Encryption at rest protects data confidentiality if physical media is compromised.

**Verification (Manual)**:
1. Navigate to Storage Account > Encryption
2. Verify encryption is enabled for all services
3. Optionally verify customer-managed key usage

**Automated Check**: `scripts/azure/check-storage.ps1` (Function: Check-StorageEncryption)

**Remediation**:
```powershell
# Encryption is enabled by default with Microsoft-managed keys
# To use customer-managed keys:

$keyVault = Get-AzKeyVault -VaultName "MyKeyVault"
$key = Get-AzKeyVaultKey -VaultName $keyVault.VaultName -Name "storage-encryption-key"

Set-AzStorageAccount -ResourceGroupName "MyRG" `
  -Name "mystorageaccount" `
  -KeyVaultEncryption `
  -KeyVaultUri $keyVault.VaultUri `
  -KeyName $key.Name
```

**Risk if Not Implemented**:
- Data exposure if storage media compromised
- Compliance violations
- Inability to meet data protection requirements

---

### AZ-STORAGE-04: Enable Soft Delete for Blobs

**CIS Reference**: 3.9
**CIS Level**: 2

**Description**: Soft delete must be enabled for blob storage with appropriate retention period to protect against accidental deletion.

**Security Impact**: Soft delete enables recovery from ransomware attacks and accidental deletions.

**Verification (Manual)**:
1. Navigate to Storage Account > Data protection
2. Verify "Enable soft delete for blobs" is checked
3. Check retention period (recommended: 30+ days)

**Automated Check**: `scripts/azure/check-storage.ps1` (Function: Check-BlobSoftDelete)

**Remediation**:
```powershell
# Enable soft delete for blobs
Enable-AzStorageBlobDeleteRetentionPolicy -ResourceGroupName "MyRG" `
  -StorageAccountName "mystorageaccount" `
  -RetentionDays 30
```

**Risk if Not Implemented**:
- Permanent data loss from accidental deletion
- No recovery from ransomware encryption
- Inability to restore malicious deletions

---

## Compute Security

### AZ-COMPUTE-01: Use Managed Disks

**CIS Reference**: 7.1
**CIS Level**: 1

**Description**: All VMs must use Azure Managed Disks instead of unmanaged disks for better security and management.

**Security Impact**: Managed disks provide encryption by default, better reliability, and simplified permissions.

**Verification (Manual)**:
1. Navigate to Virtual Machines
2. Check each VM's disk configuration
3. Verify all disks are "Managed Disk" type

**Automated Check**: `scripts/azure/check-compute.ps1` (Function: Check-ManagedDisks)

**Remediation**:
```powershell
# Convert unmanaged disks to managed disks
# WARNING: Requires VM downtime
Stop-AzVM -ResourceGroupName "MyRG" -Name "MyVM"
ConvertTo-AzVMManagedDisk -ResourceGroupName "MyRG" -VMName "MyVM"
Start-AzVM -ResourceGroupName "MyRG" -Name "MyVM"
```

**Risk if Not Implemented**:
- Complex storage account permission management
- No encryption by default
- Higher operational overhead

---

### AZ-COMPUTE-02: Enable VM Disk Encryption

**CIS Reference**: 7.2, 7.3
**CIS Level**: 1

**Description**: OS and data disks must be encrypted using Azure Disk Encryption with customer-managed keys in Key Vault.

**Security Impact**: Disk encryption protects data at rest from unauthorized access if VM or disk is compromised.

**Verification (Manual)**:
1. Navigate to Virtual Machines > Disks
2. Check encryption status for OS and data disks
3. Verify encryption uses customer-managed keys (CMK)

**Automated Check**: `scripts/azure/check-compute.ps1` (Function: Check-DiskEncryption)

**Remediation**:
```powershell
# Enable Azure Disk Encryption
$keyVault = Get-AzKeyVault -VaultName "MyKeyVault" -ResourceGroupName "MyRG"
Set-AzVMDiskEncryptionExtension -ResourceGroupName "MyRG" `
  -VMName "MyVM" `
  -DiskEncryptionKeyVaultUrl $keyVault.VaultUri `
  -DiskEncryptionKeyVaultId $keyVault.ResourceId `
  -VolumeType All
```

**Risk if Not Implemented**:
- Data exposure if disk is accessed outside VM
- Compliance violations (PCI DSS, HIPAA)
- Inability to protect data at rest

---

## Key Vault Security

### AZ-KV-01: Enable Soft Delete and Purge Protection

**CIS Reference**: 8.4
**CIS Level**: 1

**Description**: Key Vault must have soft delete and purge protection enabled to prevent permanent deletion of keys and secrets.

**Security Impact**: Protects against accidental or malicious deletion of cryptographic keys and secrets.

**Verification (Manual)**:
1. Navigate to Key Vaults
2. Check Properties
3. Verify "Soft delete" = Enabled
4. Verify "Purge protection" = Enabled

**Automated Check**: `scripts/azure/check-storage.ps1` (Function: Check-KeyVaultProtection)

**Remediation**:
```powershell
# Enable soft delete and purge protection
Update-AzKeyVault -ResourceGroupName "MyRG" `
  -VaultName "MyKeyVault" `
  -EnableSoftDelete `
  -EnablePurgeProtection
```

**Risk if Not Implemented**:
- Permanent loss of encryption keys
- Service disruption from deleted secrets
- No recovery from malicious deletion
- Data loss from lost encryption keys

---

### AZ-KV-02: Set Expiration Dates for Keys and Secrets

**CIS Reference**: 8.1, 8.2
**CIS Level**: 1

**Description**: All keys and secrets in Key Vault must have expiration dates set for regular rotation.

**Security Impact**: Regular rotation limits the exposure window if keys or secrets are compromised.

**Verification (Manual)**:
1. Navigate to Key Vault > Keys and Secrets
2. Check each key and secret
3. Verify expiration date is set

**Automated Check**: `scripts/azure/check-storage.ps1` (Function: Check-KeyVaultExpiration)

**Remediation**:
```powershell
# Set expiration date for key
$expires = (Get-Date).AddDays(365)
Set-AzKeyVaultKey -VaultName "MyKeyVault" `
  -Name "MyKey" `
  -Expires $expires

# Set expiration date for secret
Set-AzKeyVaultSecret -VaultName "MyKeyVault" `
  -Name "MySecret" `
  -Expires $expires
```

**Risk if Not Implemented**:
- Long-lived credentials increase compromise risk
- No forcing function for key rotation
- Extended exposure window for compromised secrets

---

## Summary Checklist

Use this quick reference for assessment tracking:

### Identity & Access Management
- [ ] AZ-IAM-01: MFA enabled for all privileged accounts
- [ ] AZ-IAM-02: No permanent Global Administrator assignments
- [ ] AZ-IAM-03: Guest user permissions restricted
- [ ] AZ-IAM-04: User application registration disabled

### Logging & Monitoring
- [ ] AZ-LOG-01: Activity Logs retained ≥ 365 days
- [ ] AZ-LOG-02: Defender for Cloud enabled
- [ ] AZ-LOG-03: Diagnostic logs enabled for all resources
- [ ] AZ-LOG-04: NSG flow logs enabled with retention ≥ 90 days

### Network Security
- [ ] AZ-NET-01: RDP not accessible from internet
- [ ] AZ-NET-02: SSH not accessible from internet
- [ ] AZ-NET-03: Private endpoints for PaaS services

### Storage Security
- [ ] AZ-STORAGE-01: Public blob access disabled
- [ ] AZ-STORAGE-02: Secure transfer (HTTPS) required
- [ ] AZ-STORAGE-03: Storage encryption enabled
- [ ] AZ-STORAGE-04: Soft delete enabled for blobs

### Compute Security
- [ ] AZ-COMPUTE-01: Managed disks used
- [ ] AZ-COMPUTE-02: VM disk encryption enabled

### Key Vault Security
- [ ] AZ-KV-01: Soft delete and purge protection enabled
- [ ] AZ-KV-02: Expiration dates set for keys and secrets

---

**Next**: Review [04-aws-hardening-checklist.md](04-aws-hardening-checklist.md) for AWS controls.
