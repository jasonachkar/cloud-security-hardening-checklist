#!/bin/bash
#
# Run All AWS Security Checks
#
# Description: Executes all AWS security hardening checks
# Author: Cloud Security Hardening Framework
# Version: 1.0.0
#

set -euo pipefail

# Colors
CYAN='\033[0;36m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
START_TIME=$(date +%s)

# Banner
echo -e "\n${CYAN}╔══════════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║                                                                           ║${NC}"
echo -e "${CYAN}║            AWS Security Hardening Framework                               ║${NC}"
echo -e "${CYAN}║            CIS AWS Foundations Benchmark v3.0.0                           ║${NC}"
echo -e "${CYAN}║                                                                           ║${NC}"
echo -e "${CYAN}║            Production-Grade Security Assessment Tool                      ║${NC}"
echo -e "${CYAN}║                                                                           ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════════════╝${NC}\n"

echo "Assessment Start Time: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

# Verify AWS CLI
if ! command -v aws &> /dev/null; then
    echo -e "${RED}[ERROR]${NC} AWS CLI not found. Please install AWS CLI first."
    exit 1
fi

# Verify authentication
if ! aws sts get-caller-identity &> /dev/null; then
    echo -e "${RED}[ERROR]${NC} Not authenticated to AWS. Run 'aws configure' first."
    exit 1
fi

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
ACCOUNT_ALIAS=$(aws iam list-account-aliases --query 'AccountAliases[0]' --output text 2>/dev/null || echo "N/A")

echo -e "${CYAN}[INFO]${NC} AWS Account ID: $ACCOUNT_ID"
echo -e "${CYAN}[INFO]${NC} Account Alias: $ACCOUNT_ALIAS"
echo -e "${CYAN}[INFO]${NC} Region: ${AWS_REGION:-$(aws configure get region)}"
echo ""

# Make scripts executable
chmod +x "$SCRIPT_DIR"/*.sh 2>/dev/null || true

# Security checks
declare -a checks=(
    "Identity & Access Management:check-iam.sh"
    "Logging & Monitoring:check-logging.sh"
    "Network Security:check-network.sh"
    "Storage Security:check-storage.sh"
    "Compute Security:check-compute.sh"
)

declare -a results=()
total_failures=0

# Run each check
for check in "${checks[@]}"; do
    IFS=':' read -r name script <<< "$check"
    script_path="$SCRIPT_DIR/$script"

    if [[ ! -f "$script_path" ]]; then
        echo -e "${YELLOW}[WARN]${NC} Script not found: $script_path"
        continue
    fi

    echo -e "\n${CYAN}╔══════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║  Running: $name${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════════════╝${NC}\n"

    # Execute check
    if bash "$script_path"; then
        results+=("$name:PASS")
    else
        results+=("$name:FAIL")
        ((total_failures++))
    fi
done

# Summary Report
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

echo -e "\n\n${CYAN}╔══════════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║                    ASSESSMENT SUMMARY REPORT                              ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════════════╝${NC}\n"

echo "Account: $ACCOUNT_ALIAS ($ACCOUNT_ID)"
echo "Assessment Date: $(date '+%Y-%m-%d %H:%M:%S')"
echo "Duration: $((DURATION / 60)) minutes $((DURATION % 60)) seconds"
echo ""

echo "Results by Category:"
echo "═══════════════════════════════════════════════════════════════════════════"

pass_count=0
fail_count=0

for result in "${results[@]}"; do
    IFS=':' read -r category status <<< "$result"

    if [[ "$status" == "PASS" ]]; then
        echo -e "${GREEN}✓${NC} $(printf '%-50s' "$category") [PASS]"
        ((pass_count++))
    else
        echo -e "${RED}✗${NC} $(printf '%-50s' "$category") [FAIL]"
        ((fail_count++))
    fi
done

echo ""
echo "═══════════════════════════════════════════════════════════════════════════"

total_checks=${#results[@]}
if [[ $total_checks -gt 0 ]]; then
    compliance_rate=$(awk "BEGIN {printf \"%.2f\", ($pass_count / $total_checks) * 100}")

    if (( $(echo "$compliance_rate >= 90" | bc -l) )); then
        color=$GREEN
    elif (( $(echo "$compliance_rate >= 70" | bc -l) )); then
        color=$YELLOW
    else
        color=$RED
    fi

    echo -e "\nOverall Compliance Rate: ${color}$compliance_rate%${NC}"
    echo -e "  Categories Passed: ${GREEN}$pass_count / $total_checks${NC}"
    echo -e "  Categories Failed: ${RED}$fail_count / $total_checks${NC}"
fi

echo ""
echo "═══════════════════════════════════════════════════════════════════════════"

if [[ $total_failures -gt 0 ]]; then
    echo -e "\n${RED}⚠  ACTION REQUIRED: $total_failures security check categor$(if [[ $total_failures -eq 1 ]]; then echo "y"; else echo "ies"; fi) failed${NC}"
    echo -e "${YELLOW}   Review failures above and consult remediation guide:${NC}"
    echo -e "${YELLOW}   docs/05-remediation-guide.md${NC}\n"
    exit 1
else
    echo -e "\n${GREEN}✓  All security checks passed!${NC}"
    echo -e "${GREEN}   Continue monitoring and schedule regular assessments.${NC}\n"
fi

echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  Assessment Complete                                                      ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════════════╝${NC}\n"

exit 0
