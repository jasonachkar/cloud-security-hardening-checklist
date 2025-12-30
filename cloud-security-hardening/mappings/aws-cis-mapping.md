# AWS CIS Benchmark Mapping

Quick reference mapping of framework controls to CIS Amazon Web Services Foundations Benchmark v3.0.0.

For detailed mapping information, see [docs/02-cis-mapping.md](../docs/02-cis-mapping.md).

## Control to CIS Mapping

| Framework Control | CIS Control | CIS Level | Category |
|-------------------|-------------|-----------|----------|
| AWS-IAM-01 | 1.5, 1.6 | 1 | Identity and Access Management |
| AWS-IAM-02 | 1.7 | 1 | Identity and Access Management |
| AWS-IAM-03 | 1.8 | 1 | Identity and Access Management |
| AWS-IAM-04 | 1.9, 1.10 | 1 | Identity and Access Management |
| AWS-IAM-05 | 1.11 | 1 | Identity and Access Management |
| AWS-IAM-06 | 1.12 | 1 | Identity and Access Management |
| AWS-IAM-07 | 1.13 | 1 | Identity and Access Management |
| AWS-IAM-08 | 1.14 | 1 | Identity and Access Management |
| AWS-IAM-09 | 1.16 | 1 | Identity and Access Management |
| AWS-IAM-10 | 1.17 | 1 | Identity and Access Management |
| AWS-IAM-11 | 1.19 | 1 | Identity and Access Management |
| AWS-IAM-12 | 1.20 | 1 | Identity and Access Management |
| AWS-IAM-13 | 1.21 | 1 | Identity and Access Management |
| AWS-LOG-01 | 3.1, 3.2, 3.3, 3.4 | 1 | Logging |
| AWS-LOG-02 | 3.5 | 1 | Logging |
| AWS-LOG-03 | 3.7 | 1 | Logging |
| AWS-LOG-04 | 3.8 | 1 | Logging |
| AWS-LOG-05 | 3.9 | 2 | Logging |
| AWS-LOG-06 | 3.10, 3.11 | 1, 2 | Logging |
| AWS-SEC-01 | 6.1 | 1 | Additional Security Services |
| AWS-SEC-02 | 6.2 | 2 | Additional Security Services |
| AWS-SEC-03 | 6.3 | 2 | Additional Security Services |
| AWS-NET-01 | 5.1 | 1 | Networking |
| AWS-NET-02 | 5.2 | 1 | Networking |
| AWS-NET-03 | 5.3 | 1 | Networking |
| AWS-NET-04 | 5.4 | 2 | Networking |
| AWS-NET-05 | 5.6 | 1 | Networking |
| AWS-STORAGE-01 | 2.1.1 | 1 | Storage |
| AWS-STORAGE-02 | 2.1.2 | 2 | Storage |
| AWS-STORAGE-03 | 2.1.4 | 1 | Storage |
| AWS-STORAGE-04 | 2.1.5 | 1 | Storage |
| AWS-STORAGE-05 | 2.2.1 | 2 | Storage |
| AWS-STORAGE-06 | 2.3.1 | 1 | Storage |
| AWS-STORAGE-07 | 2.3.2 | 1 | Storage |
| AWS-STORAGE-08 | 2.3.3 | 1 | Storage |

## CIS to Framework Control Mapping

### Section 1: Identity and Access Management
- **1.5** → AWS-IAM-01 (Root MFA enabled)
- **1.6** → AWS-IAM-01 (Root hardware MFA)
- **1.7** → AWS-IAM-02 (No root access keys)
- **1.8** → AWS-IAM-03 (Root not used daily)
- **1.9** → AWS-IAM-04 (Password policy minimum length)
- **1.10** → AWS-IAM-04 (Password reuse prevention)
- **1.11** → AWS-IAM-05 (MFA for console users)
- **1.12** → AWS-IAM-06 (Unused credentials disabled)
- **1.13** → AWS-IAM-07 (One active access key)
- **1.14** → AWS-IAM-08 (Access key rotation)
- **1.16** → AWS-IAM-09 (No wildcard permissions)
- **1.17** → AWS-IAM-10 (Support role created)
- **1.19** → AWS-IAM-11 (Expired certificates removed)
- **1.20** → AWS-IAM-12 (Centralized IAM management)
- **1.21** → AWS-IAM-13 (Permissions via groups)

### Section 2: Storage
- **2.1.1** → AWS-STORAGE-01 (S3 encryption at rest)
- **2.1.2** → AWS-STORAGE-02 (S3 bucket policy denies HTTP)
- **2.1.4** → AWS-STORAGE-03 (S3 data classified)
- **2.1.5** → AWS-STORAGE-04 (S3 Block Public Access)
- **2.2.1** → AWS-STORAGE-05 (EBS encryption by default)
- **2.3.1** → AWS-STORAGE-06 (RDS encryption enabled)
- **2.3.2** → AWS-STORAGE-07 (RDS auto minor version upgrade)
- **2.3.3** → AWS-STORAGE-08 (RDS not public)

### Section 3: Logging
- **3.1** → AWS-LOG-01 (CloudTrail enabled all regions)
- **3.2** → AWS-LOG-01 (CloudTrail log file validation)
- **3.3** → AWS-LOG-01 (CloudTrail S3 bucket not public)
- **3.4** → AWS-LOG-01 (CloudTrail integrated with CloudWatch)
- **3.5** → AWS-LOG-02 (Config enabled all regions)
- **3.7** → AWS-LOG-03 (CloudTrail logs encrypted)
- **3.8** → AWS-LOG-04 (KMS CMK rotation enabled)
- **3.9** → AWS-LOG-05 (VPC Flow Logs enabled)
- **3.10** → AWS-LOG-06 (S3 object logging write events)
- **3.11** → AWS-LOG-06 (S3 object logging read events)

### Section 4: Monitoring (Manual Verification Required)
- **4.1-4.14** → CloudWatch Log Metric Filters and Alarms
- Not automated in current framework version
- Requires custom metric filter and alarm configuration

### Section 5: Networking
- **5.1** → AWS-NET-01 (No NACL ingress from 0.0.0.0/0 to admin ports)
- **5.2** → AWS-NET-02 (No SG ingress from 0.0.0.0/0 to admin ports)
- **5.3** → AWS-NET-03 (Default SG restricts all traffic)
- **5.4** → AWS-NET-04 (VPC peering least access)
- **5.6** → AWS-NET-05 (IMDSv2 required)

### Section 6: Additional Security Services
- **6.1** → AWS-SEC-01 (GuardDuty enabled)
- **6.2** → AWS-SEC-02 (Security Hub enabled)
- **6.3** → AWS-SEC-03 (Config enabled - duplicate of 3.5)

## Coverage Summary

- **CIS Level 1 Controls**: 30 controls
- **CIS Level 2 Controls**: 8 controls
- **Total Coverage**: ~50% of CIS Benchmark

## Automated vs Manual Verification

| Verification Method | Control Count |
|---------------------|---------------|
| Fully Automated | 25 |
| Partially Automated | 5 |
| Manual Verification Required | 8 |

**Fully Automated**: Scripts provide complete verification
**Partially Automated**: Scripts provide partial verification, manual review needed
**Manual**: Requires manual verification (e.g., CloudWatch alarms)

## Controls Not Automated

The following CIS controls require manual verification:

1. **Section 4 - Monitoring** (4.1-4.14): CloudWatch Log Metric Filters and Alarms
2. **Section 1.15**: IAM password policy expiration
3. **Section 1.18**: IAM user contact information
4. **Section 1.22**: IAM policies attached to groups or roles

## Multi-Region Considerations

Many AWS checks are performed against the default region or all regions:
- CloudTrail: Multi-region trail check
- GuardDuty: Per-region service
- Config: Per-region service
- VPC Flow Logs: Per-region per-VPC

Scripts automatically scan all enabled regions where applicable.

---

**Reference**: CIS Amazon Web Services Foundations Benchmark v3.0.0 (January 2024)
