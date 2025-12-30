#!/bin/bash
#
# AWS Identity & Access Management (IAM) Security Checks
# CIS Amazon Web Services Foundations Benchmark v3.0.0
#
# Description: Read-only security checks for AWS IAM configuration
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

# AWS-IAM-01: Check root account MFA
check_root_mfa() {
    section "AWS-IAM-01: Root Account MFA Enabled"

    local mfa_enabled=$(aws iam get-account-summary --query 'SummaryMap.AccountMFAEnabled' --output text)

    if [[ "$mfa_enabled" == "1" ]]; then
        pass "Root account MFA is enabled - CIS 1.5"
    else
        fail "Root account MFA is NOT enabled - CIS 1.5"
        info "  Remediate: Sign in as root and enable MFA device"
    fi
}

# AWS-IAM-02: Check for root account access keys
check_root_access_keys() {
    section "AWS-IAM-02: Root Account Access Keys"

    local access_keys=$(aws iam get-account-summary --query 'SummaryMap.AccountAccessKeysPresent' --output text)

    if [[ "$access_keys" == "0" ]]; then
        pass "No root account access keys exist - CIS 1.7"
    else
        fail "Root account has access keys - CIS 1.7"
        info "  Remediate: Sign in as root and delete all access keys"
    fi
}

# AWS-IAM-03: Check root account usage
check_root_usage() {
    section "AWS-IAM-03: Root Account Usage"

    info "Checking CloudTrail for root account usage in past 30 days..."

    # Check for root user events
    local start_time=$(date -u -d '30 days ago' '+%Y-%m-%dT%H:%M:%S')
    local root_events=$(aws cloudtrail lookup-events \
        --lookup-attributes AttributeKey=Username,AttributeValue=root \
        --start-time "$start_time" \
        --max-results 1 \
        --query 'Events[0]' 2>/dev/null || echo "")

    if [[ -z "$root_events" || "$root_events" == "null" ]]; then
        pass "No root account usage detected in past 30 days - CIS 1.8"
    else
        warn "Root account has been used in past 30 days - CIS 1.8"
        info "  Best practice: Use IAM users for daily tasks"
    fi
}

# AWS-IAM-04: Check IAM password policy
check_password_policy() {
    section "AWS-IAM-04: IAM Password Policy"

    local policy=$(aws iam get-account-password-policy --query 'PasswordPolicy' 2>/dev/null || echo "")

    if [[ -z "$policy" || "$policy" == "null" ]]; then
        fail "No password policy configured - CIS 1.9, 1.10"
        info "  Remediate: aws iam update-account-password-policy"
        return
    fi

    # Check minimum length
    local min_length=$(echo "$policy" | jq -r '.MinimumPasswordLength // 0')
    if [[ $min_length -ge 14 ]]; then
        pass "Password minimum length >= 14 characters - CIS 1.9"
    else
        fail "Password minimum length < 14 characters (current: $min_length) - CIS 1.9"
    fi

    # Check password reuse prevention
    local reuse_prevention=$(echo "$policy" | jq -r '.PasswordReusePrevention // 0')
    if [[ $reuse_prevention -ge 5 ]]; then
        pass "Password reuse prevention enabled (prevent $reuse_prevention passwords) - CIS 1.10"
    else
        fail "Password reuse prevention insufficient (current: $reuse_prevention, required: 5+) - CIS 1.10"
    fi

    # Check complexity requirements
    local require_symbols=$(echo "$policy" | jq -r '.RequireSymbols')
    local require_numbers=$(echo "$policy" | jq -r '.RequireNumbers')
    local require_uppercase=$(echo "$policy" | jq -r '.RequireUppercaseCharacters')
    local require_lowercase=$(echo "$policy" | jq -r '.RequireLowercaseCharacters')

    if [[ "$require_symbols" == "true" && "$require_numbers" == "true" && \
          "$require_uppercase" == "true" && "$require_lowercase" == "true" ]]; then
        pass "Password complexity requirements enabled"
    else
        warn "Password complexity requirements not fully enabled"
    fi
}

# AWS-IAM-05: Check for MFA on console users
check_user_mfa() {
    section "AWS-IAM-05: Console Users MFA Status"

    # Get credential report
    aws iam generate-credential-report &> /dev/null
    sleep 2  # Wait for report generation

    local report=$(aws iam get-credential-report --query 'Content' --output text | base64 -d)

    local users_without_mfa=$(echo "$report" | awk -F',' 'NR>1 && $4=="true" && $8=="false" {print $1}')

    if [[ -z "$users_without_mfa" ]]; then
        pass "All console users have MFA enabled - CIS 1.11"
    else
        fail "Console users without MFA found - CIS 1.11"
        while IFS= read -r user; do
            info "  User without MFA: $user"
        done <<< "$users_without_mfa"
    fi
}

# AWS-IAM-06: Check for unused credentials
check_unused_credentials() {
    section "AWS-IAM-06: Unused Credentials (45+ days)"

    aws iam generate-credential-report &> /dev/null
    sleep 2

    local report=$(aws iam get-credential-report --query 'Content' --output text | base64 -d)

    local cutoff_date=$(date -u -d '45 days ago' '+%Y-%m-%dT%H:%M:%S')
    local unused_found=false

    while IFS=',' read -r user password_enabled password_last_used access_key_1_active access_key_1_last_used access_key_2_active access_key_2_last_used; do
        [[ "$user" == "user" ]] && continue  # Skip header

        # Check password last used
        if [[ "$password_enabled" == "true" && "$password_last_used" != "N/A" && "$password_last_used" != "no_information" ]]; then
            if [[ "$password_last_used" < "$cutoff_date" ]]; then
                warn "User $user password unused for 45+ days - CIS 1.12"
                unused_found=true
            fi
        fi

        # Check access keys
        if [[ "$access_key_1_active" == "true" && "$access_key_1_last_used" != "N/A" ]]; then
            if [[ "$access_key_1_last_used" < "$cutoff_date" ]]; then
                warn "User $user access key 1 unused for 45+ days - CIS 1.12"
                unused_found=true
            fi
        fi
    done < <(echo "$report")

    if [[ "$unused_found" == "false" ]]; then
        pass "No credentials unused for 45+ days - CIS 1.12"
    fi
}

# AWS-IAM-07: Check access key rotation
check_key_rotation() {
    section "AWS-IAM-07: Access Key Rotation (90 days)"

    aws iam generate-credential-report &> /dev/null
    sleep 2

    local report=$(aws iam get-credential-report --query 'Content' --output text | base64 -d)

    local cutoff_date=$(date -u -d '90 days ago' '+%Y-%m-%dT%H:%M:%S')
    local old_keys_found=false

    while IFS=',' read -r user _ _ _ access_key_1_active access_key_1_last_rotated access_key_2_active access_key_2_last_rotated; do
        [[ "$user" == "user" ]] && continue

        if [[ "$access_key_1_active" == "true" && "$access_key_1_last_rotated" != "N/A" ]]; then
            if [[ "$access_key_1_last_rotated" < "$cutoff_date" ]]; then
                fail "User $user access key 1 not rotated in 90+ days - CIS 1.14"
                old_keys_found=true
            fi
        fi

        if [[ "$access_key_2_active" == "true" && "$access_key_2_last_rotated" != "N/A" ]]; then
            if [[ "$access_key_2_last_rotated" < "$cutoff_date" ]]; then
                fail "User $user access key 2 not rotated in 90+ days - CIS 1.14"
                old_keys_found=true
            fi
        fi
    done < <(echo "$report")

    if [[ "$old_keys_found" == "false" ]]; then
        pass "All access keys rotated within 90 days - CIS 1.14"
    fi
}

# AWS-IAM-08: Check for wildcard permissions
check_wildcard_policies() {
    section "AWS-IAM-08: Wildcard IAM Permissions"

    local policies=$(aws iam list-policies --scope Local --query 'Policies[*].Arn' --output text)

    local wildcard_found=false

    for policy_arn in $policies; do
        local policy_version=$(aws iam get-policy --policy-arn "$policy_arn" --query 'Policy.DefaultVersionId' --output text)
        local policy_doc=$(aws iam get-policy-version --policy-arn "$policy_arn" --version-id "$policy_version" --query 'PolicyVersion.Document' --output json)

        # Check for Action:* and Resource:* combination
        if echo "$policy_doc" | jq -e '.Statement[] | select(.Effect=="Allow" and (.Action=="*" or .Action[]=="*") and (.Resource=="*" or .Resource[]=="*"))' &> /dev/null; then
            policy_name=$(aws iam get-policy --policy-arn "$policy_arn" --query 'Policy.PolicyName' --output text)
            fail "Policy with full admin privileges: $policy_name - CIS 1.16"
            wildcard_found=true
        fi
    done

    if [[ "$wildcard_found" == "false" ]]; then
        pass "No policies with full administrative privileges (*:*) - CIS 1.16"
    fi
}

# Main execution
main() {
    echo -e "\n${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║   AWS IAM Security Hardening Checks                          ║${NC}"
    echo -e "${CYAN}║   CIS AWS Foundations Benchmark v3.0.0                        ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}\n"

    check_prerequisites

    info "Starting IAM security checks...\n"

    check_root_mfa
    check_root_access_keys
    check_root_usage
    check_password_policy
    check_user_mfa
    check_unused_credentials
    check_key_rotation
    check_wildcard_policies

    # Summary
    echo -e "\n${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║   IAM Security Check Summary                                  ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}\n"

    echo -e "Results:"
    echo -e "  ${GREEN}PASS: $PASS_COUNT${NC}"
    echo -e "  ${RED}FAIL: $FAIL_COUNT${NC}"
    echo -e "  ${YELLOW}WARN: $WARN_COUNT${NC}\n"

    local total=$((PASS_COUNT + FAIL_COUNT + WARN_COUNT))
    if [[ $total -gt 0 ]]; then
        local compliance_rate=$(awk "BEGIN {printf \"%.2f\", ($PASS_COUNT / $total) * 100}")
        echo -e "Compliance Rate: $compliance_rate%\n"
    fi

    # Exit code
    if [[ $FAIL_COUNT -gt 0 ]]; then
        exit 1
    fi
    exit 0
}

main "$@"
