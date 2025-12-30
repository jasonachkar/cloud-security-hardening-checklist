# Limitations and Assumptions

## Overview

This document outlines the known limitations, assumptions, and scope boundaries of the Cloud Security Hardening Framework. Understanding these constraints is essential for appropriate use and realistic expectations.

## Framework Scope

### What This Framework IS

✅ **CIS-aligned security checklist** for Azure and AWS
✅ **Automated verification scripts** for common security controls
✅ **Remediation guidance** for failed controls
✅ **Production-ready** code for security assessments
✅ **Starting point** for comprehensive security programs
✅ **Compliance validation tool** for CIS Benchmarks

### What This Framework IS NOT

❌ **Complete security solution** - Additional security measures required
❌ **Compliance certification** - Professional audits still needed
❌ **Vulnerability scanner** - Does not detect application vulnerabilities
❌ **Penetration testing tool** - Does not actively exploit systems
❌ **Auto-remediation system** - Scripts are read-only
❌ **Real-time monitoring** - Scheduled scans only
❌ **Substitute for security expertise** - Requires knowledgeable users

---

## Technical Limitations

### 1. Read-Only Operation

**Limitation**: Scripts only assess security posture; they never modify cloud resources.

**Why**: Safety and risk mitigation. Auto-remediation could cause service disruptions.

**Workaround**: Follow manual remediation guidance in [docs/05-remediation-guide.md](05-remediation-guide.md).

**Impact**: Remediation requires manual intervention.

---

### 2. API and CLI Dependencies

**Limitation**: Scripts rely on Azure CLI (`az`), AWS CLI (`aws`), and PowerShell modules.

**Requirements**:
- **Azure**: Azure CLI v2.50+, Az PowerShell Module v10.0+
- **AWS**: AWS CLI v2.13+, bash 4.0+, jq, grep

**Risk**: CLI/API changes may break scripts until updated.

**Mitigation**:
- Pin CLI versions in CI/CD pipelines
- Test scripts before upgrading CLI tools
- Monitor cloud provider change logs

```yaml
# Example: Pin Azure CLI version
- uses: azure/CLI@v1
  with:
    azcliversion: 2.50.0
```

---

### 3. Permission Requirements

**Limitation**: Scripts require READ permissions across all services.

**Azure Minimum Permissions**:
- Reader role at subscription level
- Security Reader role (recommended)
- Access to Azure Policy, Defender for Cloud, Diagnostic Settings

**AWS Minimum Permissions**:
- SecurityAudit managed policy
- Or custom read-only policy with access to:
  - IAM, CloudTrail, Config, GuardDuty
  - EC2, VPC, S3, RDS, KMS
  - CloudWatch Logs

**Risk**: Insufficient permissions cause incomplete scans.

**Mitigation**: Verify permissions before running scans:

```powershell
# Azure: Test permissions
Get-AzRoleAssignment -SignInName user@domain.com
```

```bash
# AWS: Validate permissions
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::ACCOUNT:user/scanner \
  --action-names iam:GetAccountSummary ec2:DescribeInstances \
  --query 'EvaluationResults[?EvalDecision!=`allowed`]'
```

---

### 4. Incomplete Control Coverage

**Limitation**: Framework covers ~25 Azure and ~20 AWS controls. CIS Benchmarks contain 100+ controls each.

**Covered Areas**:
- ✅ Identity & Access Management (high priority)
- ✅ Logging & Monitoring (high priority)
- ✅ Network Security (high priority)
- ✅ Storage Security (high priority)
- ✅ Compute Security (partial)
- ⚠️ Database Security (limited)
- ⚠️ Kubernetes Security (not included)
- ⚠️ Serverless Security (limited)

**Not Covered**:
- Application-level security
- Code vulnerabilities
- Secret management in code
- Third-party integrations
- Custom applications

**Mitigation**: Supplement with additional security tools:
- **SAST/DAST**: Snyk, Checkmarx, Veracode
- **IaC Scanning**: Checkov, Terrascan, Terraform Sentinel
- **Secret Scanning**: GitGuardian, TruffleHog
- **Container Scanning**: Trivy, Aqua, Twistlock

---

### 5. Multi-Cloud Complexity

**Limitation**: Separate scripts for Azure and AWS; no unified interface.

**Challenge**: Organizations using both clouds must run separate assessments.

**Workaround**: Use wrapper scripts or CI/CD orchestration:

```bash
#!/bin/bash
# run-multicloud-scan.sh

echo "Running Azure security scan..."
cd scripts/azure && ./run-all-checks.ps1 > ../../azure-results.txt

echo "Running AWS security scan..."
cd ../aws && ./run-all-checks.sh > ../../aws-results.txt

echo "Consolidating results..."
cat azure-results.txt aws-results.txt > multicloud-report.txt
```

---

### 6. Performance at Scale

**Limitation**: Sequential checks can be slow for large environments.

**Performance Benchmarks** (approximate):
- **Small** (1 subscription/account, <100 resources): 2-5 minutes
- **Medium** (1-3 subscriptions/accounts, 100-1000 resources): 5-15 minutes
- **Large** (5+ subscriptions/accounts, 1000+ resources): 15-45 minutes
- **Enterprise** (50+ subscriptions/accounts): 45+ minutes

**Bottlenecks**:
- API rate limiting
- Large number of resources to enumerate
- CloudTrail event history queries
- Multi-region scans

**Optimization**:

```powershell
# Azure: Parallel processing
$subscriptions = Get-AzSubscription

$subscriptions | ForEach-Object -Parallel {
    Set-AzContext -SubscriptionId $_.Id
    & ./check-iam.ps1
} -ThrottleLimit 5
```

```bash
# AWS: Parallel region scanning
for region in us-east-1 us-west-2 eu-west-1; do
  (aws ec2 describe-instances --region $region &)
done
wait
```

---

### 7. Point-in-Time Assessment

**Limitation**: Scans provide snapshot at execution time, not continuous monitoring.

**Risk**: Configuration drift between scans goes undetected.

**Mitigation**:
- Schedule frequent scans (daily recommended)
- Enable cloud-native monitoring (Azure Policy, AWS Config)
- Implement change alerts
- Use CI/CD integration for pre-deployment checks

**Recommended Scan Frequency**:
- **Production**: Daily
- **Staging**: Weekly
- **Development**: Weekly or on-demand
- **Pre-deployment**: On every infrastructure change

---

### 8. False Positives/Negatives

**Limitation**: Automated checks may produce false positives (incorrect failures) or false negatives (missed issues).

**Common False Positives**:
- Approved security exceptions flagged as failures
- Legacy resources with documented waivers
- Alternative security implementations

**Common False Negatives**:
- Complex policies not fully analyzed
- Conditional access policies with subtle flaws
- Resource-level exceptions within accounts

**Mitigation**:
- Maintain exception list
- Manual validation of critical controls
- Regular script updates to improve accuracy

```powershell
# Example: Exception list for approved public storage
$approvedPublicStorage = @(
    "publicassets",
    "cdn-origin",
    "static-website"
)

if ($storageAccount.Name -in $approvedPublicStorage) {
    Write-Host "[PASS] $($storageAccount.Name) - Approved exception" -ForegroundColor Yellow
    continue
}
```

---

## Operational Assumptions

### Assumption 1: User Has Security Expertise

**Assumption**: Users understand cloud security concepts and can interpret results.

**Required Knowledge**:
- Cloud architecture (Azure/AWS)
- IAM and access control
- Network security (VPC, NSG, Security Groups)
- Encryption concepts
- Logging and monitoring

**If Assumption Violated**:
- Results may be misinterpreted
- Remediation may be incorrectly applied
- False positives not recognized

**Recommendation**: Provide training or engage security consultants.

---

### Assumption 2: Baseline Cloud Configuration Exists

**Assumption**: Cloud environment has basic structure in place (subscriptions, VPCs, IAM users).

**Not Designed For**:
- Green field deployments
- Empty cloud accounts
- Pre-production planning

**Designed For**:
- Existing cloud environments
- Security assessment of running infrastructure
- Compliance validation

---

### Assumption 3: Permissions Are Appropriate

**Assumption**: Executing user/service principal has sufficient read permissions.

**Risk If Violated**:
- Incomplete scans
- Missing security issues
- False confidence in security posture

**Verification**:

```bash
# AWS: List effective permissions
aws iam get-user-policy --user-name scanner-user --policy-name scanner-policy

# Azure: List role assignments
Get-AzRoleAssignment -SignInName scanner@domain.com | Format-Table RoleDefinitionName, Scope
```

---

### Assumption 4: Cloud APIs Are Available and Stable

**Assumption**: Cloud provider APIs are accessible and responsive.

**Potential Issues**:
- API outages
- Rate limiting
- Throttling during high load
- Region unavailability

**Mitigation**:

```bash
# Implement retry logic
for i in {1..3}; do
  aws cloudtrail describe-trails && break
  echo "Retry $i..."
  sleep 5
done
```

---

### Assumption 5: No Auto-Remediation Required

**Assumption**: Manual remediation is acceptable.

**Why**: Auto-remediation risks service disruption and requires extensive testing.

**Alternative**: Organizations requiring auto-remediation should:
- Use cloud-native tools (Azure Policy with DeployIfNotExists, AWS Config Remediation)
- Implement Infrastructure-as-Code (Terraform, ARM templates)
- Build custom remediation with approval workflows

---

## Environmental Assumptions

### Single vs. Multi-Tenant

**Assumption**: Scripts designed for single-tenant organizations.

**Limitations for Multi-Tenant**:
- MSPs managing multiple customer tenants
- Organizations with complex tenant structures
- Partner environments

**Workaround for MSPs**:

```powershell
# Loop through multiple tenants
$tenants = @("tenant1-id", "tenant2-id", "tenant3-id")

foreach ($tenant in $tenants) {
    Connect-AzAccount -Tenant $tenant
    & ./run-all-checks.ps1 > "report-$tenant.txt"
}
```

---

### Regional Coverage

**Azure**:
- ✅ Global services (IAM, subscriptions)
- ✅ Regional resources with known regions
- ⚠️ May miss resources in newly added regions

**AWS**:
- ✅ Global services (IAM, CloudTrail)
- ✅ All standard regions
- ⚠️ Opt-in regions require explicit enablement
- ❌ GovCloud and China regions not included

**Mitigation**:

```bash
# AWS: Dynamically discover all enabled regions
regions=$(aws ec2 describe-regions --query 'Regions[?OptInStatus!=`not-opted-in`].RegionName' --output text)

for region in $regions; do
  echo "Scanning $region..."
  aws ec2 describe-instances --region $region
done
```

---

## Compliance and Legal Limitations

### Not a Compliance Certification

**Important**: Running these scripts does NOT certify compliance with:
- CIS Benchmarks
- ISO 27001
- PCI DSS
- HIPAA
- SOC 2
- GDPR
- Any regulatory framework

**Reality**: Compliance requires:
- Third-party audits
- Documentation of controls
- Evidence collection
- Management attestation
- Continuous monitoring programs

**Use Case**: Scripts provide evidence for audits, but are not sufficient alone.

---

### No Legal Liability

**Disclaimer**: This framework is provided AS-IS without warranty.

**Users Are Responsible For**:
- Validating results
- Testing in their environment
- Understanding impact of changes
- Compliance with organizational policies
- Meeting regulatory requirements

**Not Responsible For**:
- Service disruptions from remediation
- Missed security issues (false negatives)
- Compliance failures
- Financial or data losses

---

## Support and Maintenance Limitations

### Community-Supported

**Support Model**: Open-source, community-maintained project.

**Available Support**:
- ✅ GitHub issues for bugs
- ✅ Documentation
- ✅ Community contributions
- ❌ No SLA
- ❌ No guaranteed response time
- ❌ No professional support

**For Enterprise Support**:
- Engage security consulting firms
- Use cloud provider support
- Hire internal expertise

---

### Update Frequency

**Maintenance**: Best-effort updates for CIS Benchmark changes and cloud provider API updates.

**No Guarantee**:
- Immediate updates for new CIS versions
- Support for all cloud services
- Compatibility with all CLI versions

**Recommendation**:
- Test scripts after cloud provider updates
- Review change logs before using new versions
- Contribute improvements back to project

---

## Recommended Complementary Tools

To address framework limitations, use these complementary tools:

| Gap | Recommended Tools |
|-----|------------------|
| Continuous monitoring | Azure Policy, AWS Config, Cloud Custodian |
| Vulnerability scanning | Qualys, Tenable, Rapid7 |
| Application security | Snyk, Checkmarx, Veracode |
| IaC security | Checkov, Terrascan, Bridgecrew |
| Secret management | HashiCorp Vault, Azure Key Vault, AWS Secrets Manager |
| Container security | Trivy, Aqua, Twistlock, Prisma Cloud |
| SIEM integration | Splunk, Azure Sentinel, AWS Security Hub |
| Compliance automation | Vanta, Drata, SecureFrame |

---

## When NOT to Use This Framework

❌ **Green field environment**: Use IaC with built-in security (Terraform with Checkov)
❌ **Real-time security**: Use SIEM and SOAR platforms
❌ **Application vulnerabilities**: Use SAST/DAST tools
❌ **Compliance certification**: Engage professional auditors
❌ **Auto-remediation required**: Use cloud-native policy enforcement
❌ **Multi-cloud unified view**: Use CSPM platforms (Prisma Cloud, Wiz, Orca)

---

## Future Enhancements

Potential improvements for future versions:

1. **Additional cloud providers**: GCP, Oracle Cloud, Alibaba Cloud
2. **More controls**: Expand coverage to 80%+ of CIS Benchmarks
3. **Kubernetes security**: EKS, AKS, GKE hardening
4. **Auto-remediation**: Optional automated fixes with approval workflows
5. **Unified reporting**: Single dashboard for multi-cloud
6. **AI-powered analysis**: ML-based anomaly detection
7. **Integration APIs**: Native integration with SIEM/SOAR
8. **Custom controls**: Framework for organization-specific checks

---

## Conclusion

This framework provides valuable security assessment capabilities but is not a complete security solution. Understanding its limitations enables appropriate use and realistic expectations.

**Key Takeaways**:
1. Read-only assessment tool, not auto-remediation
2. Covers common controls, not exhaustive
3. Point-in-time snapshot, not continuous monitoring
4. Requires security expertise to use effectively
5. Complements, but doesn't replace, comprehensive security program

**Recommended Use**:
- Part of defense-in-depth strategy
- Regular scheduled scans
- Pre-deployment security validation
- Compliance evidence collection
- Security posture trending

For questions or to report limitations not documented here, open a GitHub issue.

---

**Framework Version**: 1.0.0
**Last Updated**: December 2025
