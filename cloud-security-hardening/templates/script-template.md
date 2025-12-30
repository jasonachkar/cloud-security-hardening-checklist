# Security Check Script Template

Use this template when creating new automated security check scripts.

---

## PowerShell Script Template (Azure)

```powershell
#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Azure [Category] Security Checks

.DESCRIPTION
    Performs read-only security checks on Azure [category] including:
    - [Check 1]
    - [Check 2]
    - [Check 3]

.NOTES
    File Name: check-[category].ps1
    Author: Cloud Security Hardening Framework
    Requires: Az PowerShell Module, authenticated Azure session
    Version: 1.0.0

.EXAMPLE
    ./check-[category].ps1

.LINK
    https://github.com/your-repo/cloud-security-hardening
#>

#Requires -Modules Az.Accounts, Az.[Module]

[CmdletBinding()]
param()

# Script configuration
$ErrorActionPreference = "Continue"
$WarningPreference = "SilentlyContinue"
$Script:FailureCount = 0
$Script:PassCount = 0
$Script:WarnCount = 0

# Output formatting functions
function Write-Pass {
    param([string]$Message)
    Write-Host "[PASS] $Message" -ForegroundColor Green
    $Script:PassCount++
}

function Write-Fail {
    param([string]$Message)
    Write-Host "[FAIL] $Message" -ForegroundColor Red
    $Script:FailureCount++
}

function Write-Warn {
    param([string]$Message)
    Write-Host "[WARN] $Message" -ForegroundColor Yellow
    $Script:WarnCount++
}

function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Cyan
}

function Write-SectionHeader {
    param([string]$Title)
    Write-Host "`n========== $Title ==========" -ForegroundColor Magenta
}

# Verify Azure connection
function Test-AzureConnection {
    try {
        $context = Get-AzContext -ErrorAction Stop
        if ($null -eq $context) {
            Write-Host "[ERROR] Not connected to Azure. Run 'Connect-AzAccount' first." -ForegroundColor Red
            exit 1
        }
        Write-Info "Connected to Azure Subscription: $($context.Subscription.Name)"
        return $true
    }
    catch {
        Write-Host "[ERROR] Failed to get Azure context: $_" -ForegroundColor Red
        exit 1
    }
}

# Check function template
function Test-ControlID {
    Write-SectionHeader "CONTROL-ID: Control Description"

    try {
        $subscriptions = Get-AzSubscription

        foreach ($sub in $subscriptions) {
            Set-AzContext -SubscriptionId $sub.Id | Out-Null
            Write-Info "Checking subscription: $($sub.Name)"

            # Get resources
            $resources = Get-Az[Resource] -ErrorAction SilentlyContinue

            foreach ($resource in $resources) {
                # Check condition
                if ([condition]) {
                    Write-Pass "Resource complies: $($resource.Name) - CIS X.X"
                }
                else {
                    Write-Fail "Resource does not comply: $($resource.Name) - CIS X.X"
                    Write-Info "  Remediation: [Brief remediation hint]"
                }
            }
        }
    }
    catch {
        Write-Fail "Error checking control: $_"
    }
}

# Main execution
function Main {
    Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║   Azure [Category] Security Checks                            ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan

    Test-AzureConnection

    Write-Info "Starting [category] security checks...`n"

    # Run all checks
    Test-ControlID
    # Add more check functions here

    # Summary
    Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║   [Category] Security Check Summary                           ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan

    Write-Host "Results:" -ForegroundColor White
    Write-Host "  PASS: $Script:PassCount" -ForegroundColor Green
    Write-Host "  FAIL: $Script:FailureCount" -ForegroundColor Red
    Write-Host "  WARN: $Script:WarnCount`n" -ForegroundColor Yellow

    # Exit code based on failures
    if ($Script:FailureCount -gt 0) {
        exit 1
    }
    exit 0
}

# Execute main function
Main
```

---

## Bash Script Template (AWS)

```bash
#!/bin/bash
#
# AWS [Category] Security Checks
# CIS Amazon Web Services Foundations Benchmark v3.0.0
#
# Description: Read-only security checks for AWS [category]
# Author: Cloud Security Hardening Framework
# Version: 1.0.0
#

set -euo pipefail

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Counters
PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0

# Output functions
pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((PASS_COUNT++))
}

fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((FAIL_COUNT++))
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
    ((WARN_COUNT++))
}

info() {
    echo -e "${CYAN}[INFO]${NC} $1"
}

section() {
    echo -e "\n${CYAN}========== $1 ==========${NC}\n"
}

# Verify AWS CLI is installed and configured
check_prerequisites() {
    if ! command -v aws &> /dev/null; then
        echo -e "${RED}[ERROR]${NC} AWS CLI not found. Please install AWS CLI first."
        exit 1
    fi

    if ! aws sts get-caller-identity &> /dev/null; then
        echo -e "${RED}[ERROR]${NC} Not authenticated to AWS. Run 'aws configure' first."
        exit 1
    fi

    ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
    info "AWS Account ID: $ACCOUNT_ID"
}

# Check function template
check_control_id() {
    section "CONTROL-ID: Control Description"

    # Get resources
    local resources=$(aws [service] [command] --query '[Query]' --output text)

    for resource in $resources; do
        # Check condition
        local result=$(aws [service] [command] --resource "$resource" --query '[Query]' --output text)

        if [[ "$result" == "[expected_value]" ]]; then
            pass "Resource complies: $resource - CIS X.X"
        else
            fail "Resource does not comply: $resource - CIS X.X"
            info "  Current value: $result"
            info "  Remediation: [Brief remediation hint]"
        fi
    done
}

# Main execution
main() {
    echo -e "\n${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║   AWS [Category] Security Checks                              ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}\n"

    check_prerequisites

    info "Starting [category] security checks...`n"

    # Run all checks
    check_control_id
    # Add more check functions here

    # Summary
    echo -e "\n${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║   [Category] Security Check Summary                           ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}\n"

    echo -e "Results:"
    echo -e "  ${GREEN}PASS: $PASS_COUNT${NC}"
    echo -e "  ${RED}FAIL: $FAIL_COUNT${NC}"
    echo -e "  ${YELLOW}WARN: $WARN_COUNT${NC}\n"

    # Exit code
    if [[ $FAIL_COUNT -gt 0 ]]; then
        exit 1
    fi
    exit 0
}

main "$@"
```

---

## Script Development Guidelines

### 1. Read-Only Operations

**CRITICAL**: Scripts must NEVER modify cloud resources.

✅ **Allowed**:
- `Get-*`, `List-*`, `Describe-*` operations
- Read operations on configuration
- Querying resource properties

❌ **NEVER Use**:
- `Set-*`, `Update-*`, `Delete-*` operations
- Write operations
- Resource creation or modification

### 2. Error Handling

```powershell
# PowerShell
try {
    $result = Get-AzResource -ErrorAction Stop
}
catch {
    Write-Warn "Unable to retrieve resources: $_"
    return
}
```

```bash
# Bash
if ! result=$(aws service command 2>/dev/null); then
    warn "Unable to retrieve resources"
    return
fi
```

### 3. Output Standards

All output must use standardized format:

- `[PASS]` - Green - Control passes
- `[FAIL]` - Red - Control fails (security gap)
- `[WARN]` - Yellow - Partial compliance or needs review
- `[INFO]` - Cyan - Informational context

### 4. CIS Reference

Always include CIS control reference:

```
Write-Pass "Resource complies: $name - CIS 3.1"
pass "Resource complies: $name - CIS 3.1"
```

### 5. Exit Codes

Scripts must return appropriate exit codes for CI/CD integration:

- `exit 0` - All checks passed
- `exit 1` - One or more checks failed

### 6. Performance Considerations

```powershell
# Cache subscription list
$subscriptions = Get-AzSubscription

# Parallel processing for large environments
$subscriptions | ForEach-Object -Parallel {
    # Check logic
} -ThrottleLimit 5
```

```bash
# Parallel processing
for region in $regions; do
    (check_region "$region" &)
done
wait
```

### 7. Documentation

Every script must include:
- Synopsis
- Description
- Examples
- Required modules/tools
- Version information

---

## Testing Checklist

Before committing a new script:

- [ ] Script runs without errors in test environment
- [ ] All functions have error handling
- [ ] No modifications to cloud resources
- [ ] Output format is consistent
- [ ] CIS references are accurate
- [ ] Exit codes are appropriate
- [ ] Works across multiple subscriptions/accounts
- [ ] Documentation is complete
- [ ] Code is commented appropriately

---

**Template Version**: 1.0.0
**Last Updated**: December 2025
