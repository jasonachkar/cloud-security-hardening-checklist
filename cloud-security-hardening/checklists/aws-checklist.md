# AWS Security Hardening Checklist

Quick reference checklist for AWS security controls. For detailed information, see [docs/04-aws-hardening-checklist.md](../docs/04-aws-hardening-checklist.md).

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
| ☐ | AWS-IAM-01 | 1.5, 1.6 | Root account MFA enabled (hardware preferred) | Critical |
| ☐ | AWS-IAM-02 | 1.7 | Root account has no access keys | Critical |
| ☐ | AWS-IAM-03 | 1.8 | Root user not used for daily tasks | Critical |
| ☐ | AWS-IAM-04 | 1.9, 1.10 | IAM password policy enforced (14+ chars, complexity, rotation) | High |
| ☐ | AWS-IAM-05 | 1.11 | MFA enabled for all console users | Critical |
| ☐ | AWS-IAM-06 | 1.12 | Credentials unused for 45+ days disabled | High |
| ☐ | AWS-IAM-07 | 1.13 | Only one active access key per IAM user | High |
| ☐ | AWS-IAM-08 | 1.14 | Access keys rotated every 90 days | High |
| ☐ | AWS-IAM-09 | 1.16 | No IAM policies with full admin privileges (Action:*, Resource:*) | Critical |
| ☐ | AWS-IAM-10 | 1.17 | Support role created for incident handling | Medium |
| ☐ | AWS-IAM-11 | 1.19 | Expired SSL/TLS certificates removed | High |
| ☐ | AWS-IAM-12 | 1.20 | IAM users managed via identity federation or AWS SSO | High |
| ☐ | AWS-IAM-13 | 1.21 | IAM users receive permissions through groups (not direct attachment) | High |

**Automated Check**: `scripts/aws/check-iam.sh`

---

## Logging & Monitoring

| Status | Control ID | CIS | Description | Priority |
|--------|-----------|-----|-------------|----------|
| ☐ | AWS-LOG-01 | 3.1-3.4 | CloudTrail enabled in all regions with log file validation | Critical |
| ☐ | AWS-LOG-02 | 3.5 | AWS Config enabled in all regions | Critical |
| ☐ | AWS-LOG-03 | 3.7 | CloudTrail logs encrypted at rest using KMS CMK | High |
| ☐ | AWS-LOG-04 | 3.8 | KMS CMK rotation enabled | High |
| ☐ | AWS-LOG-05 | 3.9 | VPC Flow Logs enabled in all VPCs | High |
| ☐ | AWS-LOG-06 | 3.10, 3.11 | S3 object-level logging enabled for CloudTrail buckets | High |
| ☐ | AWS-LOG-07 | 3.6 | S3 bucket access logging enabled on CloudTrail bucket | Medium |
| ☐ | AWS-LOG-08 | 3.3 | CloudTrail S3 bucket not publicly accessible | Critical |
| ☐ | AWS-LOG-09 | Custom | CloudTrail integrated with CloudWatch Logs | High |
| ☐ | AWS-LOG-10 | 6.1 | GuardDuty enabled in all regions | Critical |

**Automated Check**: `scripts/aws/check-logging.sh`

---

## Monitoring & Alerting

| Status | Control ID | CIS | Description | Priority |
|--------|-----------|-----|-------------|----------|
| ☐ | AWS-MON-01 | 4.1 | Alarm exists for unauthorized API calls | High |
| ☐ | AWS-MON-02 | 4.2 | Alarm exists for console sign-in without MFA | High |
| ☐ | AWS-MON-03 | 4.3 | Alarm exists for root account usage | Critical |
| ☐ | AWS-MON-04 | 4.4 | Alarm exists for IAM policy changes | High |
| ☐ | AWS-MON-05 | 4.5 | Alarm exists for CloudTrail configuration changes | Critical |
| ☐ | AWS-MON-06 | 4.6 | Alarm exists for console authentication failures | High |
| ☐ | AWS-MON-07 | 4.7 | Alarm exists for disabling/deletion of CMKs | High |
| ☐ | AWS-MON-08 | 4.8 | Alarm exists for S3 bucket policy changes | High |
| ☐ | AWS-MON-09 | 4.9 | Alarm exists for AWS Config configuration changes | High |
| ☐ | AWS-MON-10 | 4.10 | Alarm exists for security group changes | High |
| ☐ | AWS-MON-11 | 4.11 | Alarm exists for NACL changes | Medium |
| ☐ | AWS-MON-12 | 4.12 | Alarm exists for network gateway changes | High |
| ☐ | AWS-MON-13 | 4.13 | Alarm exists for route table changes | High |
| ☐ | AWS-MON-14 | 4.14 | Alarm exists for VPC changes | High |

**Automated Check**: Not included in current scripts (manual verification required)

---

## Network Security

| Status | Control ID | CIS | Description | Priority |
|--------|-----------|-----|-------------|----------|
| ☐ | AWS-NET-01 | 5.1 | No NACLs allow ingress from 0.0.0.0/0 to admin ports | Critical |
| ☐ | AWS-NET-02 | 5.2 | No security groups allow ingress from 0.0.0.0/0 to admin ports (22, 3389) | Critical |
| ☐ | AWS-NET-03 | 5.3 | Default security groups restrict all traffic | Critical |
| ☐ | AWS-NET-04 | 5.4 | VPC peering routing tables are least access | Medium |
| ☐ | AWS-NET-05 | 5.6 | EC2 instances require IMDSv2 | Critical |
| ☐ | AWS-NET-06 | Custom | VPC endpoints used for AWS services | Medium |
| ☐ | AWS-NET-07 | Custom | AWS WAF enabled for internet-facing applications | High |
| ☐ | AWS-NET-08 | Custom | PrivateLink used for internal service communication | Medium |

**Automated Check**: `scripts/aws/check-network.sh`

---

## Storage Security

| Status | Control ID | CIS | Description | Priority |
|--------|-----------|-----|-------------|----------|
| ☐ | AWS-STORAGE-01 | 2.1.1 | S3 buckets employ encryption at rest | Critical |
| ☐ | AWS-STORAGE-02 | 2.1.2 | S3 bucket policies deny HTTP requests (require HTTPS) | High |
| ☐ | AWS-STORAGE-03 | 2.1.4 | S3 data discovered, classified, and secured | High |
| ☐ | AWS-STORAGE-04 | 2.1.5 | S3 buckets configured with Block Public Access | Critical |
| ☐ | AWS-STORAGE-05 | 2.2.1 | EBS encryption enabled by default | Critical |
| ☐ | AWS-STORAGE-06 | 2.3.1 | RDS instances encrypted at rest | Critical |
| ☐ | AWS-STORAGE-07 | 2.3.2 | RDS Auto Minor Version Upgrade enabled | High |
| ☐ | AWS-STORAGE-08 | 2.3.3 | RDS instances not publicly accessible | Critical |
| ☐ | AWS-STORAGE-09 | Custom | S3 versioning enabled for critical buckets | High |
| ☐ | AWS-STORAGE-10 | Custom | S3 Object Lock enabled for compliance buckets | Medium |
| ☐ | AWS-STORAGE-11 | Custom | EBS snapshots encrypted | High |
| ☐ | AWS-STORAGE-12 | Custom | S3 buckets have lifecycle policies | Medium |

**Automated Check**: `scripts/aws/check-storage.sh`

---

## Compute Security

| Status | Control ID | CIS | Description | Priority |
|--------|-----------|-----|-------------|----------|
| ☐ | AWS-COMPUTE-01 | Custom | EC2 instances launched from approved AMIs only | High |
| ☐ | AWS-COMPUTE-02 | Custom | EC2 instances use IMDSv2 | Critical |
| ☐ | AWS-COMPUTE-03 | Custom | EC2 instances have SSM agent installed | High |
| ☐ | AWS-COMPUTE-04 | Custom | EC2 instances use IAM roles (not access keys) | Critical |
| ☐ | AWS-COMPUTE-05 | Custom | Unused EBS volumes deleted | Medium |
| ☐ | AWS-COMPUTE-06 | Custom | EC2 instances have detailed monitoring enabled | Medium |
| ☐ | AWS-COMPUTE-07 | Custom | Lambda functions use least privilege IAM roles | High |
| ☐ | AWS-COMPUTE-08 | Custom | Lambda functions deployed in VPC when accessing internal resources | High |

**Automated Check**: `scripts/aws/check-compute.sh`

---

## Secrets Management

| Status | Control ID | CIS | Description | Priority |
|--------|-----------|-----|-------------|----------|
| ☐ | AWS-SEC-01 | Custom | Secrets stored in AWS Secrets Manager or Parameter Store | Critical |
| ☐ | AWS-SEC-02 | Custom | Secrets Manager automatic rotation enabled | High |
| ☐ | AWS-SEC-03 | Custom | KMS CMKs used for secrets encryption | High |
| ☐ | AWS-SEC-04 | Custom | No hardcoded secrets in Lambda environment variables | Critical |

**Automated Check**: Not included in current scripts (manual verification required)

---

## Additional Security Services

| Status | Control ID | CIS | Description | Priority |
|--------|-----------|-----|-------------|----------|
| ☐ | AWS-SVC-01 | 6.1 | GuardDuty enabled | Critical |
| ☐ | AWS-SVC-02 | 6.2 | Security Hub enabled | High |
| ☐ | AWS-SVC-03 | 6.3 | AWS Config enabled in all regions | Critical |
| ☐ | AWS-SVC-04 | Custom | Inspector enabled for vulnerability scanning | High |
| ☐ | AWS-SVC-05 | Custom | Macie enabled for sensitive data discovery | Medium |
| ☐ | AWS-SVC-06 | Custom | AWS Firewall Manager used for centralized firewall management | Medium |

**Automated Check**: Partially included in `scripts/aws/check-logging.sh`

---

## Backup & Disaster Recovery

| Status | Control ID | CIS | Description | Priority |
|--------|-----------|-----|-------------|----------|
| ☐ | AWS-BCR-01 | Custom | AWS Backup configured for critical resources | High |
| ☐ | AWS-BCR-02 | Custom | RDS automated backups enabled | Critical |
| ☐ | AWS-BCR-03 | Custom | Backup retention meets compliance requirements | High |
| ☐ | AWS-BCR-04 | Custom | Backups tested regularly | High |
| ☐ | AWS-BCR-05 | Custom | Cross-region backup replication enabled | Medium |

**Automated Check**: Not included in current scripts (manual verification required)

---

## Summary Report

**Assessment Date**: _______________
**Assessor**: _______________
**AWS Account(s)**: _______________

### Results Summary

| Category | Total | Pass | Fail | Warn | Compliance % |
|----------|-------|------|------|------|--------------|
| IAM | 13 | ___ | ___ | ___ | ___% |
| Logging | 10 | ___ | ___ | ___ | ___% |
| Monitoring | 14 | ___ | ___ | ___ | ___% |
| Network | 8 | ___ | ___ | ___ | ___% |
| Storage | 12 | ___ | ___ | ___ | ___% |
| Compute | 8 | ___ | ___ | ___ | ___% |
| Secrets | 4 | ___ | ___ | ___ | ___% |
| Services | 6 | ___ | ___ | ___ | ___% |
| Backup/DR | 5 | ___ | ___ | ___ | ___% |
| **TOTAL** | **80** | ___ | ___ | ___ | ___% |

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

```bash
# Run all checks
cd scripts/aws
./run-all-checks.sh

# Run specific category
./check-iam.sh
./check-logging.sh
./check-network.sh
./check-storage.sh
./check-compute.sh
```

### Export Results

```bash
# Generate report
./run-all-checks.sh | tee "aws-security-report-$(date +%Y-%m-%d).txt"
```

### Multi-Region Check

```bash
# Check specific regions
for region in us-east-1 us-west-2 eu-west-1; do
  echo "=== Scanning $region ==="
  AWS_REGION=$region ./run-all-checks.sh
done
```

---

## CIS Benchmark Compliance Score

Calculate your CIS compliance percentage:

```
Compliance % = (Number of PASS controls / Total applicable controls) × 100
```

**Level 1 Benchmark Target**: 95%+ compliance
**Level 2 Benchmark Target**: 90%+ compliance

---

**For detailed remediation guidance, see**: [docs/05-remediation-guide.md](../docs/05-remediation-guide.md)

**For CIS mapping, see**: [mappings/aws-cis-mapping.md](../mappings/aws-cis-mapping.md)
