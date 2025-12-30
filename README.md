# Cloud Security Hardening Framework

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Azure CIS](https://img.shields.io/badge/Azure-CIS%20v2.0.0-0078D4?logo=microsoft-azure)](https://www.cisecurity.org/benchmark/azure)
[![AWS CIS](https://img.shields.io/badge/AWS-CIS%20v3.0.0-FF9900?logo=amazon-aws)](https://www.cisecurity.org/benchmark/amazon_web_services)
[![PowerShell](https://img.shields.io/badge/PowerShell-7.0+-5391FE?logo=powershell)](https://github.com/PowerShell/PowerShell)
[![Bash](https://img.shields.io/badge/Bash-4.0+-4EAA25?logo=gnu-bash)](https://www.gnu.org/software/bash/)
[![Read-only](https://img.shields.io/badge/Mode-Read--Only-success)](#safety--operating-model)

> **Production-grade, read-only cloud security hardening checks & guidance for Microsoft Azure and Amazon Web Services.**  
> CIS-aligned controls, automated verification scripts, standardized reporting, and actionable remediation guidance.

---

## 📌 Why this repo exists

Cloud environments drift. Security configurations change. This framework helps you **continuously validate** key hardening controls against CIS Benchmarks and identify gaps **without modifying resources**.

Use it to:
- Assess posture against CIS Benchmarks (Azure v2.0.0 / AWS v3.0.0)
- Detect misconfigurations across common control categories
- Generate consistent reports for audits, reviews, and CI/CD gates
- Provide remediation guidance for each failing control

---

## 📋 Table of Contents

- [Key Features](#-key-features)
- [Safety & Operating Model](#-safety--operating-model)
- [Repository Structure](#-repository-structure)
- [Quick Start](#-quick-start)
  - [Azure](#azure)
  - [AWS](#aws)
- [Usage](#-usage)
  - [Run all checks](#run-all-checks)
  - [Run a specific category](#run-a-specific-category)
  - [Save a report](#save-a-report)
- [Controls Coverage](#-controls-coverage)
- [CI/CD Integration](#-cicd-integration)
  - [GitHub Actions](#github-actions)
  - [Azure DevOps](#azure-devops)
  - [GitLab CI](#gitlab-ci)
- [Configuration](#-configuration)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)
- [Roadmap](#-roadmap)
- [Security](#-security)
- [License](#-license)
- [Acknowledgments](#-acknowledgments)

---

## ✨ Key Features

- **CIS-aligned controls** with mappings and references
- **Read-only verification scripts** (PowerShell for Azure, Bash for AWS)
- **Standardized reporting**: `[PASS] [FAIL] [WARN] [INFO]` with control identifiers
- **Actionable remediation guidance** in `docs/`
- **CI/CD-friendly** exit codes and pipeline examples
- **Scalable**: supports multi-subscription / multi-account / multi-region patterns

---

## ✅ Safety & Operating Model

This framework is designed to be safe for production environments:

- ✅ **Read-only checks only** (no resource modifications)
- ✅ **No credentials stored** in scripts
- ✅ Uses native cloud tooling (**Azure CLI / Az PowerShell / AWS CLI**) for visibility
- ✅ Findings are auditable via cloud provider logs

> **Note:** Reports may contain sensitive metadata (resource names, IDs, policy state). Treat outputs as sensitive.

---

## 🏗 Repository Structure

```text
cloud-security-hardening/
├── README.md
├── LICENSE
│
├── docs/
│   ├── 00-overview.md
│   ├── 01-threat-model-context.md
│   ├── 02-cis-mapping.md
│   ├── 03-azure-hardening-checklist.md
│   ├── 04-aws-hardening-checklist.md
│   ├── 05-remediation-guide.md
│   ├── 06-ci-cd-integration.md
│   └── 07-limitations-and-assumptions.md
│
├── checklists/
│   ├── azure-checklist.md
│   └── aws-checklist.md
│
├── scripts/
│   ├── azure/
│   │   ├── check-iam.ps1
│   │   ├── check-logging.ps1
│   │   ├── check-network.ps1
│   │   ├── check-storage.ps1
│   │   ├── check-compute.ps1
│   │   └── run-all-checks.ps1
│   └── aws/
│       ├── check-iam.sh
│       ├── check-logging.sh
│       ├── check-network.sh
│       ├── check-storage.sh
│       ├── check-compute.sh
│       └── run-all-checks.sh
│
├── output/
│   ├── sample-azure-report.txt
│   └── sample-aws-report.txt
│
├── mappings/
│   ├── azure-cis-mapping.md
│   └── aws-cis-mapping.md
│
└── templates/
    ├── control-template.md
    └── script-template.md
```
## 🚀 Quick Start

### Azure

#### Prerequisites

* Azure CLI **2.50.0+**
* PowerShell **7.0+**
* Az PowerShell Module **10.0+**
* Permissions: **Reader** (minimum), **Security Reader** (recommended)

#### Setup

```bash
# Install Azure CLI (macOS)
brew install azure-cli

# Install PowerShell (macOS)
brew install --cask powershell

# Install Az PowerShell module
pwsh -Command "Install-Module -Name Az -Force -AllowClobber -Scope CurrentUser"

# Authenticate
az login
pwsh -Command "Connect-AzAccount"
```

#### Run

```bash
git clone https://github.com/yourusername/cloud-security-hardening.git
cd cloud-security-hardening/scripts/azure

pwsh ./run-all-checks.ps1
```

---

### AWS

#### Prerequisites

* AWS CLI **2.13.0+**
* Bash **4.0+**
* `jq` **1.6+**
* Permissions: `SecurityAudit` managed policy (recommended) or equivalent read-only policy

#### Setup

```bash
# Install AWS CLI (macOS)
brew install awscli

# Install jq (macOS)
brew install jq

# Configure credentials
aws configure

# Verify authentication
aws sts get-caller-identity
```

#### Run

```bash
git clone https://github.com/yourusername/cloud-security-hardening.git
cd cloud-security-hardening/scripts/aws

chmod +x ./*.sh
./run-all-checks.sh
```

---

## 💻 Usage

### Run all checks

**Azure**

```bash
cd scripts/azure
pwsh ./run-all-checks.ps1
```

**AWS**

```bash
cd scripts/aws
./run-all-checks.sh
```

### Run a specific category

**Azure**

```bash
pwsh ./check-iam.ps1
pwsh ./check-network.ps1
pwsh ./check-storage.ps1
```

**AWS**

```bash
./check-iam.sh
./check-logging.sh
./check-network.sh
```

### Save a report

**Azure**

```bash
cd scripts/azure
pwsh ./run-all-checks.ps1 | Tee-Object -FilePath "../../reports/azure-$(Get-Date -Format 'yyyy-MM-dd').txt"
```

**AWS**

```bash
cd scripts/aws
./run-all-checks.sh | tee "../../reports/aws-$(date +%Y-%m-%d).txt"
```

---

## 🧾 Controls Coverage

> The exact control IDs and mappings live in `mappings/` and the detailed procedures in `docs/`.

### Azure (30+ controls)

* Identity & Access: MFA, RBAC, PIM, guest access restrictions
* Logging & Monitoring: Activity Logs, Defender for Cloud, diagnostic settings
* Network: NSGs, secure ingress patterns, flow logs
* Storage: encryption, secure transfer, public access posture
* Compute: VM baseline signals, disk encryption posture, endpoint protection signals
* Key Vault: soft delete, purge protection, expiration policies

### AWS (25+ controls)

* IAM: root MFA, access key hygiene, password policies, permissions
* Logging: CloudTrail, Config, GuardDuty, VPC Flow Logs
* Network: security groups, NACL posture, IMDSv2
* Storage: S3 block public access, encryption posture, EBS/RDS encryption posture
* Compute: EC2 IAM roles, baseline checks, Lambda networking posture (where applicable)

---

## 📊 Output Format

All scripts emit standardized lines:

* `[PASS]` Control implemented correctly
* `[FAIL]` Security gap identified (remediation required)
* `[WARN]` Partial/ambiguous state (needs review)
* `[INFO]` Informational finding

Example:

```text
========== AZ-STORAGE-01: Secure Transfer Required ==========
[PASS] Secure transfer (HTTPS) required: prodstorageacct - CIS 3.1
[FAIL] Secure transfer not required: devstorageacct - CIS 3.1
```

---

## 🔄 CI/CD Integration

### GitHub Actions

```yaml
name: Cloud Security Scan

on:
  schedule:
    - cron: "0 2 * * *" # daily at 2 AM UTC
  push:
    branches: [main]

jobs:
  azure-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Azure Login
        uses: azure/login@v1
        with:
          creds: ${{ secrets.AZURE_CREDENTIALS }}

      - name: Run Azure Security Checks
        run: |
          cd scripts/azure
          pwsh ./run-all-checks.ps1

      - name: Upload Report Artifacts
        uses: actions/upload-artifact@v4
        with:
          name: azure-security-report
          path: reports/**/*
```

### Azure DevOps

```yaml
trigger:
  - main

schedules:
  - cron: "0 2 * * *"
    displayName: Daily security scan
    branches:
      include:
        - main

pool:
  vmImage: ubuntu-latest

steps:
  - task: PowerShell@2
    displayName: Run Azure security checks
    inputs:
      targetType: filePath
      filePath: scripts/azure/run-all-checks.ps1
      pwsh: true
```

### GitLab CI

```yaml
security-scan:
  stage: test
  image: mcr.microsoft.com/azure-cli
  script:
    - az login --service-principal -u "$AZURE_CLIENT_ID" -p "$AZURE_CLIENT_SECRET" --tenant "$AZURE_TENANT_ID"
    - cd scripts/azure
    - pwsh ./run-all-checks.ps1
  artifacts:
    paths:
      - reports/
    expire_in: 90 days
  only:
    - schedules
```

> More examples and patterns: see `docs/06-ci-cd-integration.md`.

---

## ⚙️ Configuration

### Environment Variables

**Azure**

```powershell
$env:AZURE_SUBSCRIPTION_ID = "00000000-0000-0000-0000-000000000000"
$env:AZURE_ENVIRONMENT     = "AzureCloud" # AzureUSGovernment, AzureChinaCloud, etc.
```

**AWS**

```bash
export AWS_REGION=us-east-1
export AWS_DEFAULT_OUTPUT=json
export AWS_PROFILE=production
```

### Tuning thresholds (examples)

**Azure (`scripts/azure/check-storage.ps1`)**

```powershell
$MinimumTlsVersion     = "TLS1_2"
$RequiredRetentionDays = 365
```

**AWS (`scripts/aws/check-iam.sh`)**

```bash
UNUSED_CREDENTIALS_DAYS=45
KEY_ROTATION_DAYS=90
```

---

## 🔧 Troubleshooting

### Azure: “Not connected to Azure”

```powershell
Connect-AzAccount
az login
```

### Azure: “Insufficient permissions”

* Minimum: **Reader**
* Recommended: **Security Reader**

```powershell
Get-AzRoleAssignment -SignInName "you@domain.com"
```

### AWS: “Unable to locate credentials”

```bash
aws configure
aws sts get-caller-identity
```

### AWS: Rate limiting

* Reduce parallelization or add exponential backoff in orchestration scripts.

```bash
for i in {1..3}; do
  aws cloudtrail describe-trails && break
  sleep $((2**i))
done
```

### Debug mode

**Azure**

```powershell
$VerbosePreference = "Continue"
pwsh ./check-iam.ps1
```

**AWS**

```bash
set -x
./check-iam.sh
set +x
```

---

## 🤝 Contributing

Contributions are welcome.

### Rules of engagement

* ✅ Read-only checks only (no remediation/mutation)
* ✅ Keep output format consistent
* ✅ Include CIS control references where applicable
* ✅ Add documentation updates for new controls
* ✅ Test in non-production environments first

### Typical workflow

```bash
git checkout -b feature/my-new-control
# make changes
git commit -m "feat: add AZ-SQL-01 control verification (CIS 4.1.1)"
git push origin feature/my-new-control
```

---

## 🗺️ Roadmap

### v1.1 (Q4 2025)

* Microsoft Graph integration (expanded Entra ID checks)
* AWS Organizations support
* Azure Management Groups support
* JSON/XML report outputs

### v1.5 (Q1 2026)

* Additional AWS compute controls (Lambda/ECS/Fargate)
* Azure database controls
* Multi-cloud unified reporting
* IaC validation (Terraform/CloudFormation)

### v2.0 (Q2 2026)

* GCP support
* Kubernetes controls (AKS/EKS/GKE)
* Optional auto-remediation with approval workflows
* Web dashboard + API

---

## 🔐 Security

### Reporting security issues

Please **do not** open a public issue for security concerns.

Email: `security@yourcompany.com`

---

## 📄 License

Licensed under the **MIT License**. See [LICENSE](./LICENSE).

---

## 🙏 Acknowledgments

Inspired by:

* CIS Benchmarks
* ScoutSuite
* Prowler
* Microsoft Defender for Cloud

Built with:

* Azure CLI / Az PowerShell
* AWS CLI
* PowerShell
* Bash + jq

---

<div align="center">

**⭐ Star this repo if you find it useful.**
Made with ❤️ by security engineers, for security engineers.

</div>

