#!/bin/bash
# AWS Compute Security Checks - CIS AWS Foundations Benchmark v3.0.0

set -euo pipefail
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
PASS_COUNT=0; FAIL_COUNT=0; WARN_COUNT=0

pass() { echo -e "${GREEN}[PASS]${NC} $1"; ((PASS_COUNT++)); }
fail() { echo -e "${RED}[FAIL]${NC} $1"; ((FAIL_COUNT++)); }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; ((WARN_COUNT++)); }
info() { echo -e "${CYAN}[INFO]${NC} $1"; }
section() { echo -e "\n${CYAN}========== $1 ==========${NC}\n"; }

# Check EC2 instances
check_ec2_instances() {
    section "AWS-COMPUTE: EC2 Instance Security"

    local instances=$(aws ec2 describe-instances --query 'Reservations[*].Instances[*].[InstanceId,State.Name,MetadataOptions.HttpTokens]' --output text)

    while read -r instance_id state http_tokens; do
        [[ -z "$instance_id" || "$state" != "running" ]] && continue

        info "Checking instance: $instance_id"

        # IMDSv2
        if [[ "$http_tokens" == "required" ]]; then
            pass "Instance uses IMDSv2: $instance_id"
        else
            fail "Instance does not require IMDSv2: $instance_id"
        fi

        # Check if using IAM role
        local iam_role=$(aws ec2 describe-instances --instance-ids "$instance_id" --query 'Reservations[0].Instances[0].IamInstanceProfile.Arn' --output text)
        if [[ -n "$iam_role" && "$iam_role" != "None" ]]; then
            pass "Instance uses IAM role: $instance_id"
        else
            warn "Instance does not use IAM role: $instance_id"
        fi
    done <<< "$instances"
}

# Check Lambda functions
check_lambda_functions() {
    section "AWS-COMPUTE: Lambda Function Security"

    local functions=$(aws lambda list-functions --query 'Functions[*].FunctionName' --output text)

    for func in $functions; do
        # Check if in VPC (for internal resource access)
        local vpc_config=$(aws lambda get-function-configuration --function-name "$func" --query 'VpcConfig.VpcId' --output text)

        if [[ -n "$vpc_config" && "$vpc_config" != "None" ]]; then
            info "Lambda function in VPC: $func"
        else
            info "Lambda function not in VPC: $func (OK if no internal resource access needed)"
        fi

        # Check environment variables for secrets
        local env_vars=$(aws lambda get-function-configuration --function-name "$func" --query 'Environment.Variables' --output json 2>/dev/null || echo "{}")

        # Look for potential secrets in environment variable names
        if echo "$env_vars" | jq -r 'keys[]' | grep -iE '(password|secret|key|token|api)' &>/dev/null; then
            warn "Lambda function may have secrets in environment variables: $func"
            info "  Recommendation: Use AWS Secrets Manager or Parameter Store"
        fi
    done
}

main() {
    echo -e "\n${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║   AWS Compute Security Checks                                 ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}\n"

    check_ec2_instances
    check_lambda_functions

    echo -e "\n${CYAN}=== Summary ===${NC}"
    echo -e "${GREEN}PASS: $PASS_COUNT${NC} | ${RED}FAIL: $FAIL_COUNT${NC} | ${YELLOW}WARN: $WARN_COUNT${NC}\n"
    [[ $FAIL_COUNT -gt 0 ]] && exit 1
    exit 0
}

main "$@"
