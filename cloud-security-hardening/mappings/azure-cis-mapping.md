# Azure CIS Benchmark Mapping

Quick reference mapping of framework controls to CIS Microsoft Azure Foundations Benchmark v2.0.0.

For detailed mapping information, see [docs/02-cis-mapping.md](../docs/02-cis-mapping.md).

## Control to CIS Mapping

| Framework Control | CIS Control | CIS Level | Category |
|-------------------|-------------|-----------|----------|
| AZ-IAM-01 | 1.1.1, 1.1.2, 1.2.1 | 1 | Identity and Access Management |
| AZ-IAM-02 | 1.1.3 | 1 | Identity and Access Management |
| AZ-IAM-03 | 1.5, 1.7, 1.8, 1.9 | 1 | Identity and Access Management |
| AZ-IAM-04 | 1.4 | 1 | Identity and Access Management |
| AZ-LOG-01 | 5.1.1, 5.1.2 | 1 | Logging and Monitoring |
| AZ-LOG-02 | 2.1.15 | 1 | Microsoft Defender for Cloud |
| AZ-LOG-03 | 2.1.1-2.1.8, 2.1.16 | 1, 2 | Microsoft Defender for Cloud |
| AZ-LOG-04 | 5.1.3, 5.1.4 | 1 | Logging and Monitoring |
| AZ-LOG-05 | 6.6 | 2 | Networking |
| AZ-NET-01 | 6.1 | 1 | Networking |
| AZ-NET-02 | 6.2 | 1 | Networking |
| AZ-NET-03 | 6.3 | 1 | Networking |
| AZ-NET-04 | 6.4 | 1 | Networking |
| AZ-NET-05 | 6.5 | 2 | Networking |
| AZ-STORAGE-01 | 3.1 | 1 | Storage Accounts |
| AZ-STORAGE-02 | 3.2, 3.6 | 1 | Storage Accounts |
| AZ-STORAGE-03 | 3.3, 3.4 | 1 | Storage Accounts |
| AZ-STORAGE-04 | 3.5 | 2 | Storage Accounts |
| AZ-STORAGE-05 | 3.7 | 1 | Storage Accounts |
| AZ-STORAGE-06 | 3.8 | 1 | Storage Accounts |
| AZ-STORAGE-07 | 3.9 | 2 | Storage Accounts |
| AZ-STORAGE-08 | 3.10 | 2 | Storage Accounts |
| AZ-COMPUTE-01 | 7.1 | 1 | Virtual Machines |
| AZ-COMPUTE-02 | 7.2 | 1 | Virtual Machines |
| AZ-COMPUTE-03 | 7.3 | 1 | Virtual Machines |
| AZ-COMPUTE-04 | 7.4 | 1 | Virtual Machines |
| AZ-COMPUTE-05 | 7.5 | 1 | Virtual Machines |
| AZ-KV-01 | 8.1 | 1 | Key Vault |
| AZ-KV-02 | 8.2 | 1 | Key Vault |
| AZ-KV-03 | 8.3 | 1 | Key Vault |
| AZ-KV-04 | 8.4 | 1 | Key Vault |
| AZ-KV-05 | 8.5 | 2 | Key Vault |

## CIS to Framework Control Mapping

### Section 1: Identity and Access Management
- **1.1.1** → AZ-IAM-01 (MFA for privileged users)
- **1.1.2** → AZ-IAM-01 (MFA for non-privileged users)
- **1.1.3** → AZ-IAM-02 (No permanent Global Admin)
- **1.4** → AZ-IAM-04 (User app registration disabled)
- **1.5** → AZ-IAM-03 (Guest user permissions limited)
- **1.7-1.9** → AZ-IAM-03 (Guest invite restrictions)

### Section 2: Microsoft Defender for Cloud
- **2.1.1-2.1.8** → AZ-LOG-03 (Defender enabled for all services)
- **2.1.15** → AZ-LOG-02 (Auto-provisioning enabled)
- **2.1.16** → AZ-LOG-03 (Security alert emails)

### Section 3: Storage Accounts
- **3.1** → AZ-STORAGE-01 (Secure transfer required)
- **3.2** → AZ-STORAGE-02 (Public blob access disabled)
- **3.3, 3.4** → AZ-STORAGE-03 (Encryption enabled)
- **3.5** → AZ-STORAGE-04 (Customer-managed keys)
- **3.6** → AZ-STORAGE-02 (Public access disabled)
- **3.7** → AZ-STORAGE-05 (Default network access denied)
- **3.8** → AZ-STORAGE-06 (Trusted MS Services)
- **3.9** → AZ-STORAGE-07 (Soft delete enabled)
- **3.10** → AZ-STORAGE-08 (SAS token expiration)

### Section 5: Logging and Monitoring
- **5.1.1** → AZ-LOG-01 (Diagnostic setting exists)
- **5.1.2** → AZ-LOG-01 (Activity Log retention >= 365 days)
- **5.1.3** → AZ-LOG-04 (Diagnostic logs for all services)
- **5.1.4** → AZ-LOG-04 (Key Vault logging)

### Section 6: Networking
- **6.1** → AZ-NET-01 (RDP restricted from internet)
- **6.2** → AZ-NET-02 (SSH restricted from internet)
- **6.3** → AZ-NET-03 (NSG no allow-all rules)
- **6.4** → AZ-NET-04 (HTTP/HTTPS restricted)
- **6.5** → AZ-NET-05 (Network Watcher enabled)
- **6.6** → AZ-LOG-05 (NSG flow logs retention >= 90 days)

### Section 7: Virtual Machines
- **7.1** → AZ-COMPUTE-01 (Managed disks)
- **7.2** → AZ-COMPUTE-02 (OS/Data disk encryption)
- **7.3** → AZ-COMPUTE-03 (Unattached disk encryption)
- **7.4** → AZ-COMPUTE-04 (Approved extensions)
- **7.5** → AZ-COMPUTE-05 (Endpoint protection)

### Section 8: Key Vault
- **8.1** → AZ-KV-01 (Key expiration dates)
- **8.2** → AZ-KV-02 (Secret expiration dates)
- **8.3** → AZ-KV-03 (Resource locks)
- **8.4** → AZ-KV-04 (Soft delete & purge protection)
- **8.5** → AZ-KV-05 (RBAC for Key Vault)

## Coverage Summary

- **CIS Level 1 Controls**: 35 controls
- **CIS Level 2 Controls**: 10 controls
- **Total Coverage**: ~60% of CIS Benchmark

## Automated vs Manual Verification

| Verification Method | Control Count |
|---------------------|---------------|
| Fully Automated | 15 |
| Partially Automated | 10 |
| Manual Verification Required | 5 |

**Fully Automated**: Scripts provide complete verification
**Partially Automated**: Scripts provide partial verification, manual review needed
**Manual**: Requires manual portal verification or Microsoft Graph module

---

**Reference**: CIS Microsoft Azure Foundations Benchmark v2.0.0 (July 2023)
