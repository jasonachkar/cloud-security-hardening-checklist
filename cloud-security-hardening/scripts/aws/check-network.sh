#!/bin/bash
# AWS Network Security Checks - CIS AWS Foundations Benchmark v3.0.0

set -euo pipefail
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
PASS_COUNT=0; FAIL_COUNT=0; WARN_COUNT=0

pass() { echo -e "${GREEN}[PASS]${NC} $1"; ((PASS_COUNT++)); }
fail() { echo -e "${RED}[FAIL]${NC} $1"; ((FAIL_COUNT++)); }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; ((WARN_COUNT++)); }
info() { echo -e "${CYAN}[INFO]${NC} $1"; }
section() { echo -e "\n${CYAN}========== $1 ==========${NC}\n"; }

# Check Security Groups
check_security_groups() {
    section "AWS-NET-01/02: Security Group Rules"

    local sgs=$(aws ec2 describe-security-groups --query 'SecurityGroups[*].GroupId' --output text)

    for sg in $sgs; do
        local sg_name=$(aws ec2 describe-security-groups --group-ids "$sg" --query 'SecurityGroups[0].GroupName' --output text)
        local rules=$(aws ec2 describe-security-groups --group-ids "$sg" --query 'SecurityGroups[0].IpPermissions' --output json)

        # Check for 0.0.0.0/0 ingress on admin ports
        local dangerous_rules=$(echo "$rules" | jq -r '.[] | select(.IpRanges[]?.CidrIp == "0.0.0.0/0") | select(.FromPort == 22 or .FromPort == 3389 or .FromPort == 3306 or .FromPort == 1433 or .FromPort == 5432)')

        if [[ -n "$dangerous_rules" ]]; then
            fail "Security group allows admin ports from 0.0.0.0/0: $sg_name ($sg) - CIS 5.2"
        else
            pass "Security group does not allow admin ports from internet: $sg_name"
        fi

        # Check default SG
        if [[ "$sg_name" == "default" ]]; then
            if [[ $(echo "$rules" | jq 'length') -eq 0 ]]; then
                pass "Default security group restricts all traffic: $sg - CIS 5.3"
            else
                fail "Default security group allows traffic: $sg - CIS 5.3"
            fi
        fi
    done
}

# Check EC2 IMDSv2
check_imdsv2() {
    section "AWS-NET-05: EC2 IMDSv2"

    local instances=$(aws ec2 describe-instances --query 'Reservations[*].Instances[*].[InstanceId,MetadataOptions.HttpTokens]' --output text)

    while read -r instance_id http_tokens; do
        [[ -z "$instance_id" ]] && continue

        if [[ "$http_tokens" == "required" ]]; then
            pass "Instance requires IMDSv2: $instance_id - CIS 5.6"
        else
            fail "Instance allows IMDSv1: $instance_id - CIS 5.6"
        fi
    done <<< "$instances"
}

main() {
    echo -e "\n${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║   AWS Network Security Checks                                 ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}\n"

    check_security_groups
    check_imdsv2

    echo -e "\n${CYAN}=== Summary ===${NC}"
    echo -e "${GREEN}PASS: $PASS_COUNT${NC} | ${RED}FAIL: $FAIL_COUNT${NC} | ${YELLOW}WARN: $WARN_COUNT${NC}\n"
    [[ $FAIL_COUNT -gt 0 ]] && exit 1
    exit 0
}

main "$@"
