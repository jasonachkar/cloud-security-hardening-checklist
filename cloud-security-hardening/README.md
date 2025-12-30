# Cloud Security Hardening Framework

**Production-Grade Security Hardening Checklists and Automation for Azure and AWS**

## Overview

This repository provides enterprise-ready cloud security hardening checklists, automated verification scripts, and remediation guidance aligned with CIS Benchmarks for Microsoft Azure and Amazon Web Services (AWS).

Designed for cloud security engineers, consultants, and DevSecOps teams conducting security assessments, compliance audits, and continuous security validation.

## What's Included

- **CIS-Aligned Security Checklists**: Comprehensive hardening controls for Azure and AWS
- **Automated Verification Scripts**: Read-only security posture assessment tools
- **Remediation Guidance**: Step-by-step instructions to fix security gaps
- **CI/CD Integration Examples**: Integrate security checks into your pipelines
- **CIS Benchmark Mappings**: Direct traceability to CIS controls
- **Sample Reports**: Example output from security assessments

## Repository Structure

```
cloud-security-hardening/
├── README.md                           # This file
├── LICENSE                             # MIT License
│
├── docs/                               # Comprehensive documentation
│   ├── 00-overview.md                  # Framework overview
│   ├── 01-threat-model-context.md      # Threat modeling context
│   ├── 02-cis-mapping.md               # CIS Benchmark mappings
│   ├── 03-azure-hardening-checklist.md # Azure security controls
│   ├── 04-aws-hardening-checklist.md   # AWS security controls
│   ├── 05-remediation-guide.md         # Detailed remediation steps
│   ├── 06-ci-cd-integration.md         # Pipeline integration guide
│   └── 07-limitations-and-assumptions.md # Known limitations
│
├── checklists/                         # Quick reference checklists
│   ├── azure-checklist.md              # Azure controls summary
│   └── aws-checklist.md                # AWS controls summary
│
├── scripts/                            # Automated verification scripts
│   ├── azure/                          # Azure PowerShell scripts
│   │   ├── check-iam.ps1               # Identity & Access checks
│   │   ├── check-logging.ps1           # Logging & Monitoring checks
│   │   ├── check-network.ps1           # Network security checks
│   │   ├── check-storage.ps1           # Storage security checks
│   │   ├── check-compute.ps1           # Compute security checks
│   │   └── run-all-checks.ps1          # Execute all checks
│   │
│   └── aws/                            # AWS Bash scripts
│       ├── check-iam.sh                # IAM security checks
│       ├── check-logging.sh            # CloudTrail/CloudWatch checks
│       ├── check-network.sh            # VPC/Security Group checks
│       ├── check-storage.sh            # S3/EBS encryption checks
│       ├── check-compute.sh            # EC2/Lambda security checks
│       └── run-all-checks.sh           # Execute all checks
│
├── output/                             # Sample assessment reports
│   ├── sample-azure-report.txt         # Example Azure scan output
│   └── sample-aws-report.txt           # Example AWS scan output
│
├── mappings/                           # CIS Benchmark mappings
│   ├── azure-cis-mapping.md            # Azure CIS control mapping
│   └── aws-cis-mapping.md              # AWS CIS control mapping
│
└── templates/                          # Documentation templates
    ├── control-template.md             # Control documentation template
    └── script-template.md              # Script development template
```

## Who This Is For

- **Cloud Security Engineers**: Conducting security assessments and hardening
- **Security Consultants**: Delivering enterprise cloud security engagements
- **DevSecOps Teams**: Implementing security automation in CI/CD pipelines
- **Compliance Teams**: Validating CIS Benchmark compliance
- **Security Architects**: Designing secure cloud architectures

## Quick Start

### Prerequisites

**For Azure:**
- Azure CLI (`az`) installed and configured
- Azure PowerShell module installed
- Authenticated to Azure (`az login`)
- Read permissions on subscriptions to be assessed

**For AWS:**
- AWS CLI (`aws`) installed and configured
- Authenticated with credentials (`aws configure`)
- Read permissions on accounts to be assessed (SecurityAudit policy recommended)

### Running Azure Security Checks

```powershell
# Navigate to Azure scripts directory
cd scripts/azure

# Run all security checks
./run-all-checks.ps1

# Or run individual category checks
./check-iam.ps1
./check-logging.ps1
./check-network.ps1
./check-storage.ps1
./check-compute.ps1
```

### Running AWS Security Checks

```bash
# Navigate to AWS scripts directory
cd scripts/aws

# Make scripts executable
chmod +x *.sh

# Run all security checks
./run-all-checks.sh

# Or run individual category checks
./check-iam.sh
./check-logging.sh
./check-network.sh
./check-storage.sh
./check-compute.sh
```

## Understanding Results

Scripts output standardized results:

- **[PASS]**: Control is properly implemented
- **[FAIL]**: Security gap identified - remediation required
- **[WARN]**: Partial implementation or configuration needs review
- **[INFO]**: Informational finding

Example output:
```
[PASS] Azure Activity Logs enabled for all regions
[FAIL] Storage accounts allow public blob access (3 accounts)
[WARN] NSG flow logs enabled but retention < 90 days
[INFO] Subscription: Production (abc123-def456)
```

## Required Permissions

### Azure
- **Reader** role at subscription level (minimum)
- **Security Reader** role recommended for comprehensive checks
- Access to Azure Policy, Microsoft Defender for Cloud, and Diagnostic Settings

### AWS
- **SecurityAudit** managed policy (recommended)
- Or custom policy with read-only permissions for:
  - IAM, CloudTrail, Config, GuardDuty
  - EC2, VPC, S3, RDS, KMS
  - CloudWatch Logs

## CI/CD Integration

Integrate security checks into your pipelines to fail builds on security violations.

### GitHub Actions Example

```yaml
name: Cloud Security Scan
on: [push, pull_request]

jobs:
  azure-security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Azure Login
        uses: azure/login@v1
        with:
          creds: ${{ secrets.AZURE_CREDENTIALS }}
      - name: Run Azure Security Checks
        run: |
          cd scripts/azure
          pwsh ./run-all-checks.ps1
          if [ $? -ne 0 ]; then exit 1; fi
```

See [docs/06-ci-cd-integration.md](docs/06-ci-cd-integration.md) for detailed integration examples.

## CIS Benchmark Alignment

This framework aligns with:

- **Azure**: CIS Microsoft Azure Foundations Benchmark v2.0.0
- **AWS**: CIS Amazon Web Services Foundations Benchmark v3.0.0

See [mappings/](mappings/) directory for detailed control mappings.

## Remediation Guidance

Each control includes:
1. **Manual verification steps**: How to check manually via console
2. **Automated verification**: Script reference
3. **Remediation steps**: Step-by-step fix instructions
4. **Risk context**: Why this control matters

Detailed remediation guidance: [docs/05-remediation-guide.md](docs/05-remediation-guide.md)

## Limitations and Assumptions

- Scripts are **read-only** and never modify cloud resources
- Requires appropriate read permissions
- Not a substitute for professional security audits
- Should be used as part of a comprehensive security program
- Results should be validated and contextualized for your environment

See [docs/07-limitations-and-assumptions.md](docs/07-limitations-and-assumptions.md) for complete details.

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request with clear description
4. Ensure scripts remain read-only and safe

## Support and Issues

For questions, issues, or feature requests, please open a GitHub issue.

## Disclaimer

This framework provides security guidance and automation tools for cloud security assessments. It is provided as-is without warranty. Users are responsible for:

- Validating findings in their specific environment
- Testing scripts in non-production environments first
- Understanding the security controls before implementation
- Compliance with organizational policies and regulations

This is not a substitute for professional security consulting or compliance audits.

## License

MIT License - See [LICENSE](LICENSE) file for details.

## Version

**Version**: 1.0.0
**Last Updated**: December 2025
**Maintained By**: Cloud Security Engineering Team

---

**Questions?** Review the [documentation](docs/) or open an issue.
