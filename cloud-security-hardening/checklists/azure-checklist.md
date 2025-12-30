# Azure Security Hardening Checklist

Quick reference checklist for Azure security controls. For detailed information, see [docs/03-azure-hardening-checklist.md](../docs/03-azure-hardening-checklist.md).

## Assessment Tracking

Use this checklist during security assessments. Mark items as:
- ✅ **PASS**: Control implemented correctly
- ❌ **FAIL**: Control not implemented or misconfigured
- ⚠️ **WARN**: Partial implementation or needs review
- ⏭️ **SKIP**: Not applicable to environment

---

## Identity & Access Management

| Status | Control ID | CIS | Description | Priority |
|--------|-----------|-----|-------------|----------|
| ☐ | AZ-IAM-01 | 1.1.1 | MFA enabled for all privileged accounts | Critical |
| ☐ | AZ-IAM-02 | 1.1.3 | No permanent Global Administrator assignments (use PIM) | Critical |
| ☐ | AZ-IAM-03 | 1.5, 1.7-1.9 | Guest user permissions restricted | High |
| ☐ | AZ-IAM-04 | 1.4 | User application registration disabled | High |
| ☐ | AZ-IAM-05 | 1.3 | Azure AD admin portal access restricted | Medium |
| ☐ | AZ-IAM-06 | Custom | Service principal credentials reviewed and rotated | High |
| ☐ | AZ-IAM-07 | Custom | Conditional Access policies enforced | High |
| ☐ | AZ-IAM-08 | Custom | Password policy meets requirements (14+ chars) | High |

**Automated Check**: `scripts/azure/check-iam.ps1`

---

## Logging & Monitoring

| Status | Control ID | CIS | Description | Priority |
|--------|-----------|-----|-------------|----------|
| ☐ | AZ-LOG-01 | 5.1.1, 5.1.2 | Activity Log retention ≥ 365 days, exported to Log Analytics | Critical |
| ☐ | AZ-LOG-02 | 2.1.15 | Microsoft Defender for Cloud auto-provisioning enabled | Critical |
| ☐ | AZ-LOG-03 | 2.1.1-2.1.8 | Defender for Cloud enabled for all workload types | Critical |
| ☐ | AZ-LOG-04 | 5.1.3, 5.1.4 | Diagnostic logs enabled for all resources | Critical |
| ☐ | AZ-LOG-05 | 6.6 | NSG flow logs enabled with retention ≥ 90 days | High |
| ☐ | AZ-LOG-06 | 5.1.4 | Key Vault logging enabled | High |
| ☐ | AZ-LOG-07 | 5.2.1-5.2.5 | Activity Log alerts configured for critical operations | High |
| ☐ | AZ-LOG-08 | Custom | Diagnostic settings export to Storage for long-term retention | Medium |

**Automated Check**: `scripts/azure/check-logging.ps1`

---

## Network Security

| Status | Control ID | CIS | Description | Priority |
|--------|-----------|-----|-------------|----------|
| ☐ | AZ-NET-01 | 6.1 | RDP (3389) not accessible from internet (0.0.0.0/0) | Critical |
| ☐ | AZ-NET-02 | 6.2 | SSH (22) not accessible from internet (0.0.0.0/0) | Critical |
| ☐ | AZ-NET-03 | 6.3 | NSGs do not allow all inbound traffic | Critical |
| ☐ | AZ-NET-04 | 6.4 | HTTP/HTTPS access from internet restricted | High |
| ☐ | AZ-NET-05 | 6.5 | Network Watcher enabled in all regions | High |
| ☐ | AZ-NET-06 | Custom | Private Endpoints used for PaaS services | High |
| ☐ | AZ-NET-07 | Custom | DDoS Protection Standard enabled for critical VNets | Medium |
| ☐ | AZ-NET-08 | Custom | Azure Firewall or NVA deployed for egress filtering | Medium |

**Automated Check**: `scripts/azure/check-network.ps1`

---

## Storage Security

| Status | Control ID | CIS | Description | Priority |
|--------|-----------|-----|-------------|----------|
| ☐ | AZ-STORAGE-01 | 3.1 | Secure transfer (HTTPS) required for all storage accounts | Critical |
| ☐ | AZ-STORAGE-02 | 3.2, 3.6 | Public blob access disabled at account and container levels | Critical |
| ☐ | AZ-STORAGE-03 | 3.3, 3.4 | Encryption enabled for all storage services (Blob, File, Queue, Table) | Critical |
| ☐ | AZ-STORAGE-04 | 3.5 | Customer-managed keys (CMK) used for encryption | High |
| ☐ | AZ-STORAGE-05 | 3.7 | Default network access for storage accounts denied | High |
| ☐ | AZ-STORAGE-06 | 3.8 | Trusted Microsoft Services enabled for storage access | High |
| ☐ | AZ-STORAGE-07 | 3.9 | Soft delete enabled for blobs and containers | High |
| ☐ | AZ-STORAGE-08 | 3.10 | SAS token expiration ≤ 1 hour | Medium |
| ☐ | AZ-STORAGE-09 | Custom | Storage account firewall configured | High |
| ☐ | AZ-STORAGE-10 | Custom | Minimum TLS version set to 1.2 | Critical |

**Automated Check**: `scripts/azure/check-storage.ps1`

---

## Compute Security

| Status | Control ID | CIS | Description | Priority |
|--------|-----------|-----|-------------|----------|
| ☐ | AZ-COMPUTE-01 | 7.1 | Virtual machines use managed disks | High |
| ☐ | AZ-COMPUTE-02 | 7.2 | OS and data disks encrypted with CMK | Critical |
| ☐ | AZ-COMPUTE-03 | 7.3 | Unattached disks encrypted | High |
| ☐ | AZ-COMPUTE-04 | 7.4 | Only approved VM extensions installed | Medium |
| ☐ | AZ-COMPUTE-05 | 7.5 | Endpoint protection installed on all VMs | High |
| ☐ | AZ-COMPUTE-06 | Custom | System updates/patches applied regularly | High |
| ☐ | AZ-COMPUTE-07 | Custom | Just-in-Time VM access enabled | High |
| ☐ | AZ-COMPUTE-08 | Custom | Azure Bastion used for secure VM access | Medium |

**Automated Check**: `scripts/azure/check-compute.ps1`

---

## Key Vault Security

| Status | Control ID | CIS | Description | Priority |
|--------|-----------|-----|-------------|----------|
| ☐ | AZ-KV-01 | 8.1 | Expiration date set on all keys | High |
| ☐ | AZ-KV-02 | 8.2 | Expiration date set on all secrets | High |
| ☐ | AZ-KV-03 | 8.3 | Resource locks set for Key Vaults | High |
| ☐ | AZ-KV-04 | 8.4 | Soft delete and purge protection enabled | Critical |
| ☐ | AZ-KV-05 | 8.5 | RBAC enabled for Key Vault (not access policies) | High |
| ☐ | AZ-KV-06 | Custom | Key Vault firewall configured | High |
| ☐ | AZ-KV-07 | Custom | Private Endpoint configured for Key Vault | Medium |
| ☐ | AZ-KV-08 | Custom | Diagnostic logging enabled for Key Vault | Critical |

**Automated Check**: Included in `scripts/azure/check-storage.ps1`

---

## Database Security

| Status | Control ID | CIS | Description | Priority |
|--------|-----------|-----|-------------|----------|
| ☐ | AZ-DB-01 | Custom | SQL Database auditing enabled | Critical |
| ☐ | AZ-DB-02 | Custom | Transparent Data Encryption (TDE) enabled | Critical |
| ☐ | AZ-DB-03 | Custom | SQL Advanced Threat Protection enabled | High |
| ☐ | AZ-DB-04 | Custom | SQL firewall rules restrict access | Critical |
| ☐ | AZ-DB-05 | Custom | AAD authentication configured for SQL | High |
| ☐ | AZ-DB-06 | Custom | Private endpoints used for database access | High |

**Automated Check**: Not included in current scripts (manual verification required)

---

## Governance & Compliance

| Status | Control ID | CIS | Description | Priority |
|--------|-----------|-----|-------------|----------|
| ☐ | AZ-GOV-01 | Custom | Azure Policy assignments for CIS Benchmark | High |
| ☐ | AZ-GOV-02 | Custom | Resource tags enforced via policy | Medium |
| ☐ | AZ-GOV-03 | Custom | Management groups structure implemented | Medium |
| ☐ | AZ-GOV-04 | Custom | Azure Blueprints used for environment deployment | Medium |
| ☐ | AZ-GOV-05 | Custom | Resource locks on critical resources | High |

**Automated Check**: Not included in current scripts (manual verification required)

---

## Summary Report

**Assessment Date**: _______________
**Assessor**: _______________
**Azure Subscription(s)**: _______________

### Results Summary

| Category | Total | Pass | Fail | Warn | Compliance % |
|----------|-------|------|------|------|--------------|
| IAM | 8 | ___ | ___ | ___ | ___% |
| Logging | 8 | ___ | ___ | ___ | ___% |
| Network | 8 | ___ | ___ | ___ | ___% |
| Storage | 10 | ___ | ___ | ___ | ___% |
| Compute | 8 | ___ | ___ | ___ | ___% |
| Key Vault | 8 | ___ | ___ | ___ | ___% |
| Database | 6 | ___ | ___ | ___ | ___% |
| Governance | 5 | ___ | ___ | ___ | ___% |
| **TOTAL** | **61** | ___ | ___ | ___ | ___% |

### Critical Findings (Immediate Action Required)

1. _______________________________________________
2. _______________________________________________
3. _______________________________________________

### High Priority Findings (Action Within 7 Days)

1. _______________________________________________
2. _______________________________________________
3. _______________________________________________

### Remediation Plan

| Finding | Assigned To | Target Date | Status |
|---------|-------------|-------------|--------|
| | | | |
| | | | |
| | | | |

---

## Quick Commands

### Run Automated Checks

```powershell
# Run all checks
cd scripts/azure
./run-all-checks.ps1

# Run specific category
./check-iam.ps1
./check-logging.ps1
./check-network.ps1
./check-storage.ps1
./check-compute.ps1
```

### Export Results

```powershell
# Generate report
./run-all-checks.ps1 | Tee-Object -FilePath "azure-security-report-$(Get-Date -Format 'yyyy-MM-dd').txt"
```

---

**For detailed remediation guidance, see**: [docs/05-remediation-guide.md](../docs/05-remediation-guide.md)

**For CIS mapping, see**: [mappings/azure-cis-mapping.md](../mappings/azure-cis-mapping.md)
