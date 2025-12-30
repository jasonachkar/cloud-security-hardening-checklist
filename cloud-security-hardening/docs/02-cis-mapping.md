# CIS Benchmark Mapping

## Overview

This document maps the Cloud Security Hardening Framework controls to specific CIS Benchmark controls for both Azure and AWS. This mapping enables compliance reporting, audit evidence collection, and traceability to industry standards.

## CIS Benchmark Versions

- **Azure**: CIS Microsoft Azure Foundations Benchmark v2.0.0
- **AWS**: CIS Amazon Web Services Foundations Benchmark v3.0.0

## About CIS Benchmarks

The Center for Internet Security (CIS) Benchmarks are consensus-based security configuration baselines developed by cybersecurity experts worldwide. They represent industry best practices for securely configuring cloud platforms.

### CIS Benchmark Structure

CIS controls are organized into sections:

1. **Identity and Access Management**
2. **Microsoft Defender for Cloud** (Azure) / **Monitoring** (AWS)
3. **Storage Accounts** (Azure) / **Logging** (AWS)
4. **Database Services**
5. **Logging and Monitoring**
6. **Networking**
7. **Virtual Machines** (Azure) / **EC2** (AWS)
8. **Other Security Considerations**

### Scoring Levels

- **Level 1**: Basic security measures, minimal impact on business functionality
- **Level 2**: Defense-in-depth measures, may impact business functionality or cost

## Azure CIS Benchmark Mapping

### Section 1: Identity and Access Management

| Framework Control | CIS Control | CIS Level | Description |
|------------------|-------------|-----------|-------------|
| AZ-IAM-01 | 1.1.1 | 1 | Ensure that multi-factor authentication is enabled for all privileged users |
| AZ-IAM-01 | 1.1.2 | 1 | Ensure that multi-factor authentication is enabled for all non-privileged users |
| AZ-IAM-02 | 1.1.3 | 1 | Ensure that there are no guest users |
| AZ-IAM-03 | 1.2.1 | 1 | Ensure that multi-factor authentication status is 'Enabled' for all privileged users |
| AZ-IAM-04 | 1.2.2 | 2 | Ensure that 'Allow users to remember multi-factor authentication on devices they trust' is disabled |
| AZ-IAM-05 | 1.3 | 1 | Ensure that 'Restrict access to Azure AD administration portal' is set to 'Yes' |
| AZ-IAM-06 | 1.4 | 1 | Ensure that 'Users can register applications' is set to 'No' |
| AZ-IAM-07 | 1.5 | 1 | Ensure that 'Guest users permissions are limited' is set to 'Yes' |
| AZ-IAM-08 | 1.6 | 1 | Ensure that 'Members can invite' is set to 'No' |
| AZ-IAM-09 | 1.7 | 1 | Ensure that 'Guests can invite' is set to 'No' |
| AZ-IAM-10 | 1.10 | 1 | Ensure that 'Require Multi-Factor Auth to join devices' is set to 'Yes' |

### Section 2: Microsoft Defender for Cloud

| Framework Control | CIS Control | CIS Level | Description |
|------------------|-------------|-----------|-------------|
| AZ-LOG-03 | 2.1.1 | 1 | Ensure that Microsoft Defender for Cloud is set to 'On' for Servers |
| AZ-LOG-03 | 2.1.2 | 1 | Ensure that Microsoft Defender for Cloud is set to 'On' for App Service |
| AZ-LOG-03 | 2.1.3 | 2 | Ensure that Microsoft Defender for Cloud is set to 'On' for Azure SQL Databases |
| AZ-LOG-03 | 2.1.4 | 2 | Ensure that Microsoft Defender for Cloud is set to 'On' for SQL servers on machines |
| AZ-LOG-03 | 2.1.5 | 2 | Ensure that Microsoft Defender for Cloud is set to 'On' for Storage |
| AZ-LOG-03 | 2.1.6 | 2 | Ensure that Microsoft Defender for Cloud is set to 'On' for Kubernetes |
| AZ-LOG-03 | 2.1.7 | 2 | Ensure that Microsoft Defender for Cloud is set to 'On' for Container Registries |
| AZ-LOG-03 | 2.1.8 | 2 | Ensure that Microsoft Defender for Cloud is set to 'On' for Key Vault |
| AZ-LOG-02 | 2.1.15 | 1 | Ensure that 'Auto provisioning of monitoring agent' is set to 'On' |
| AZ-LOG-03 | 2.1.16 | 1 | Ensure that 'Security Alert Emails' are set |

### Section 3: Storage Accounts

| Framework Control | CIS Control | CIS Level | Description |
|------------------|-------------|-----------|-------------|
| AZ-STORAGE-01 | 3.1 | 1 | Ensure that 'Secure transfer required' is set to 'Enabled' |
| AZ-STORAGE-02 | 3.2 | 1 | Ensure that 'Enable Blob Public Access' is set to 'Disabled' |
| AZ-STORAGE-03 | 3.3 | 1 | Ensure that storage account encryption is enabled for Queue Service |
| AZ-STORAGE-03 | 3.4 | 1 | Ensure that storage account encryption is enabled for Table Service |
| AZ-STORAGE-04 | 3.5 | 2 | Ensure that storage account encryption is enabled using customer-managed keys |
| AZ-STORAGE-05 | 3.6 | 1 | Ensure that storage accounts do not allow public access to all containers |
| AZ-STORAGE-06 | 3.7 | 1 | Ensure default network access for storage accounts is denied |
| AZ-STORAGE-07 | 3.8 | 1 | Ensure 'Trusted Microsoft Services' is enabled for storage account access |
| AZ-STORAGE-08 | 3.9 | 2 | Ensure that soft delete is enabled for Azure Containers and Blob Storage |
| AZ-STORAGE-09 | 3.10 | 2 | Ensure that storage account access using shared access signatures expires within an hour |

### Section 5: Logging and Monitoring

| Framework Control | CIS Control | CIS Level | Description |
|------------------|-------------|-----------|-------------|
| AZ-LOG-01 | 5.1.1 | 1 | Ensure that a 'Diagnostic Setting' exists |
| AZ-LOG-01 | 5.1.2 | 1 | Ensure that Activity Log retention is set to 365 days or greater |
| AZ-LOG-01 | 5.1.3 | 1 | Ensure that diagnostic logs are enabled for all services that support it |
| AZ-LOG-04 | 5.1.4 | 2 | Ensure that logging for Azure Key Vault is 'Enabled' |
| AZ-LOG-05 | 5.2.1 | 1 | Ensure that Activity Log Alert exists for Create Policy Assignment |
| AZ-LOG-05 | 5.2.2 | 1 | Ensure that Activity Log Alert exists for Delete Policy Assignment |
| AZ-LOG-05 | 5.2.3 | 1 | Ensure that Activity Log Alert exists for Create or Update Network Security Group |
| AZ-LOG-05 | 5.2.4 | 1 | Ensure that Activity Log Alert exists for Delete Network Security Group |
| AZ-LOG-05 | 5.2.5 | 1 | Ensure that Activity Log Alert exists for Create or Update Security Solution |

### Section 6: Networking

| Framework Control | CIS Control | CIS Level | Description |
|------------------|-------------|-----------|-------------|
| AZ-NET-01 | 6.1 | 1 | Ensure that RDP access is restricted from the internet |
| AZ-NET-02 | 6.2 | 1 | Ensure that SSH access is restricted from the internet |
| AZ-NET-03 | 6.3 | 1 | Ensure that Network Security Groups have no inbound rules that allow all traffic |
| AZ-NET-04 | 6.4 | 1 | Ensure that HTTP(S) access from the internet is evaluated and restricted |
| AZ-NET-05 | 6.5 | 2 | Ensure that Network Watcher is 'Enabled' for all regions |
| AZ-NET-06 | 6.6 | 2 | Ensure that the Network Security Group flow log retention period is 'greater than 90 days' |

### Section 7: Virtual Machines

| Framework Control | CIS Control | CIS Level | Description |
|------------------|-------------|-----------|-------------|
| AZ-COMPUTE-01 | 7.1 | 1 | Ensure Virtual Machines are utilizing Managed Disks |
| AZ-COMPUTE-02 | 7.2 | 1 | Ensure that 'OS and Data' disks are encrypted with Customer Managed Key |
| AZ-COMPUTE-03 | 7.3 | 1 | Ensure that 'Unattached disks' are encrypted |
| AZ-COMPUTE-04 | 7.4 | 1 | Ensure that only approved extensions are installed |
| AZ-COMPUTE-05 | 7.5 | 1 | Ensure that the endpoint protection for all virtual machines is installed |

### Section 8: Key Vault

| Framework Control | CIS Control | CIS Level | Description |
|------------------|-------------|-----------|-------------|
| AZ-KV-01 | 8.1 | 1 | Ensure that the expiration date is set on all keys |
| AZ-KV-02 | 8.2 | 1 | Ensure that the expiration date is set on all secrets |
| AZ-KV-03 | 8.3 | 1 | Ensure that Resource Locks are set for mission critical Azure resources |
| AZ-KV-04 | 8.4 | 1 | Ensure that key vault is recoverable (soft delete and purge protection) |
| AZ-KV-05 | 8.5 | 2 | Enable role-based access control for Azure Key Vault |

## AWS CIS Benchmark Mapping

### Section 1: Identity and Access Management

| Framework Control | CIS Control | CIS Level | Description |
|------------------|-------------|-----------|-------------|
| AWS-IAM-01 | 1.5 | 1 | Ensure MFA is enabled for the root user account |
| AWS-IAM-02 | 1.6 | 1 | Ensure hardware MFA is enabled for the root user account |
| AWS-IAM-03 | 1.7 | 1 | Eliminate use of the root user for administrative and daily tasks |
| AWS-IAM-04 | 1.8 | 1 | Ensure IAM password policy requires minimum length of 14 or greater |
| AWS-IAM-05 | 1.9 | 1 | Ensure IAM password policy prevents password reuse |
| AWS-IAM-06 | 1.10 | 1 | Ensure multi-factor authentication is enabled for all IAM users with a console password |
| AWS-IAM-07 | 1.12 | 1 | Ensure credentials unused for 45 days or greater are disabled |
| AWS-IAM-08 | 1.13 | 1 | Ensure there is only one active access key per IAM user |
| AWS-IAM-09 | 1.14 | 1 | Ensure access keys are rotated every 90 days or less |
| AWS-IAM-10 | 1.16 | 1 | Ensure IAM policies that allow full administrative privileges are not attached |
| AWS-IAM-11 | 1.17 | 1 | Ensure a support role has been created for incident handling |
| AWS-IAM-12 | 1.19 | 1 | Ensure that all expired SSL/TLS certificates are removed |
| AWS-IAM-13 | 1.20 | 1 | Ensure IAM users are managed centrally via identity federation or AWS Organizations |
| AWS-IAM-14 | 1.21 | 1 | Ensure IAM users receive permissions only through groups |

### Section 2: Storage (S3)

| Framework Control | CIS Control | CIS Level | Description |
|------------------|-------------|-----------|-------------|
| AWS-STORAGE-01 | 2.1.1 | 1 | Ensure all S3 buckets employ encryption-at-rest |
| AWS-STORAGE-02 | 2.1.2 | 2 | Ensure S3 Bucket Policy is set to deny HTTP requests |
| AWS-STORAGE-03 | 2.1.4 | 1 | Ensure all data in S3 has been discovered, classified and secured |
| AWS-STORAGE-04 | 2.1.5 | 2 | Ensure that S3 buckets are configured with Block Public Access |
| AWS-STORAGE-05 | 2.2.1 | 2 | Ensure EBS volume encryption is enabled |
| AWS-STORAGE-06 | 2.3.1 | 1 | Ensure that encryption is enabled for RDS instances |
| AWS-STORAGE-07 | 2.3.2 | 1 | Ensure Auto Minor Version Upgrade is enabled for RDS instances |
| AWS-STORAGE-08 | 2.3.3 | 1 | Ensure that public access is not given to RDS instances |

### Section 3: Logging

| Framework Control | CIS Control | CIS Level | Description |
|------------------|-------------|-----------|-------------|
| AWS-LOG-01 | 3.1 | 1 | Ensure CloudTrail is enabled in all regions |
| AWS-LOG-01 | 3.2 | 1 | Ensure CloudTrail log file validation is enabled |
| AWS-LOG-01 | 3.3 | 1 | Ensure the S3 bucket used to store CloudTrail logs is not publicly accessible |
| AWS-LOG-01 | 3.4 | 1 | Ensure CloudTrail trails are integrated with CloudWatch Logs |
| AWS-LOG-02 | 3.5 | 1 | Ensure AWS Config is enabled in all regions |
| AWS-LOG-02 | 3.6 | 2 | Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket |
| AWS-LOG-03 | 3.7 | 1 | Ensure CloudTrail logs are encrypted at rest using KMS CMKs |
| AWS-LOG-04 | 3.8 | 1 | Ensure rotation for customer created CMKs is enabled |
| AWS-LOG-05 | 3.9 | 2 | Ensure VPC flow logging is enabled in all VPCs |
| AWS-LOG-06 | 3.10 | 1 | Ensure that Object-level logging for write events is enabled for S3 buckets |
| AWS-LOG-06 | 3.11 | 2 | Ensure that Object-level logging for read events is enabled for S3 buckets |

### Section 4: Monitoring

| Framework Control | CIS Control | CIS Level | Description |
|------------------|-------------|-----------|-------------|
| AWS-MON-01 | 4.1 | 1 | Ensure a log metric filter and alarm exist for unauthorized API calls |
| AWS-MON-02 | 4.2 | 1 | Ensure a log metric filter and alarm exist for Management Console sign-in without MFA |
| AWS-MON-03 | 4.3 | 1 | Ensure a log metric filter and alarm exist for usage of root account |
| AWS-MON-04 | 4.4 | 1 | Ensure a log metric filter and alarm exist for IAM policy changes |
| AWS-MON-05 | 4.5 | 1 | Ensure a log metric filter and alarm exist for CloudTrail configuration changes |
| AWS-MON-06 | 4.6 | 1 | Ensure a log metric filter and alarm exist for AWS Management Console authentication failures |
| AWS-MON-07 | 4.7 | 2 | Ensure a log metric filter and alarm exist for disabling or scheduled deletion of CMKs |
| AWS-MON-08 | 4.8 | 2 | Ensure a log metric filter and alarm exist for S3 bucket policy changes |
| AWS-MON-09 | 4.9 | 2 | Ensure a log metric filter and alarm exist for AWS Config configuration changes |
| AWS-MON-10 | 4.10 | 2 | Ensure a log metric filter and alarm exist for security group changes |
| AWS-MON-11 | 4.11 | 2 | Ensure a log metric filter and alarm exist for NACL changes |
| AWS-MON-12 | 4.12 | 1 | Ensure a log metric filter and alarm exist for changes to network gateways |
| AWS-MON-13 | 4.13 | 1 | Ensure a log metric filter and alarm exist for route table changes |
| AWS-MON-14 | 4.14 | 1 | Ensure a log metric filter and alarm exist for VPC changes |

### Section 5: Networking

| Framework Control | CIS Control | CIS Level | Description |
|------------------|-------------|-----------|-------------|
| AWS-NET-01 | 5.1 | 1 | Ensure no Network ACLs allow ingress from 0.0.0.0/0 to remote server administration ports |
| AWS-NET-02 | 5.2 | 1 | Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports |
| AWS-NET-03 | 5.3 | 1 | Ensure the default security group restricts all traffic |
| AWS-NET-04 | 5.4 | 2 | Ensure routing tables for VPC peering are least access |
| AWS-NET-05 | 5.6 | 1 | Ensure that EC2 Metadata Service only allows IMDSv2 |

### Section 6: Additional Security Services

| Framework Control | CIS Control | CIS Level | Description |
|------------------|-------------|-----------|-------------|
| AWS-SEC-01 | 6.1 | 1 | Ensure GuardDuty is enabled |
| AWS-SEC-02 | 6.2 | 2 | Ensure Security Hub is enabled |
| AWS-SEC-03 | 6.3 | 2 | Ensure AWS Config is enabled in all regions |

## Using CIS Mappings

### Compliance Reporting

Use the mapping to generate compliance reports:

```
CIS Azure Benchmark v2.0.0 Compliance Report
=============================================
Section 1 (IAM): 8/10 controls implemented (80%)
Section 2 (Defender): 5/7 controls implemented (71%)
Section 3 (Storage): 9/9 controls implemented (100%)
...
Overall Compliance: 85% (68/80 controls)
```

### Audit Evidence

Map framework findings to CIS controls for audit documentation:

```
Finding: Storage accounts allow public access
CIS Control: 3.2 - Ensure 'Enable Blob Public Access' is disabled
Severity: High
Status: FAIL
Remediation: See AZ-STORAGE-02
```

### Gap Analysis

Identify which CIS controls are not yet addressed:

1. Run framework scripts
2. Map FAIL findings to CIS controls
3. Prioritize based on CIS Level (Level 1 first)
4. Track remediation progress

## Implementation Priority

### Level 1 Controls (Foundational)

Implement all Level 1 controls first - these are fundamental security measures with minimal business impact.

**Priority Order**:
1. IAM and MFA controls
2. Logging and monitoring
3. Network security
4. Storage security
5. Compute security

### Level 2 Controls (Defense in Depth)

Implement Level 2 controls for enhanced security posture. These may require additional cost or complexity.

**Considerations**:
- Additional cloud service costs (e.g., GuardDuty, Defender plans)
- Potential impact on application performance
- Operational overhead for key management

## Mapping Maintenance

This mapping is maintained to reflect:
- Updates to CIS Benchmarks
- New cloud service offerings
- Evolving security best practices
- Community feedback

**Current Versions**:
- Azure CIS Benchmark: v2.0.0 (July 2023)
- AWS CIS Benchmark: v3.0.0 (January 2024)

---

**Next**: Review detailed checklists in [03-azure-hardening-checklist.md](03-azure-hardening-checklist.md) and [04-aws-hardening-checklist.md](04-aws-hardening-checklist.md).
