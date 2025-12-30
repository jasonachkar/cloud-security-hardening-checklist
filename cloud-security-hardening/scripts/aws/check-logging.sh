#!/bin/bash
#
# AWS Logging & Monitoring Security Checks
# CIS AWS Foundations Benchmark v3.0.0
#

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
PASS_COUNT=0; FAIL_COUNT=0; WARN_COUNT=0

pass() { echo -e "${GREEN}[PASS]${NC} $1"; ((PASS_COUNT++)); }
fail() { echo -e "${RED}[FAIL]${NC} $1"; ((FAIL_COUNT++)); }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; ((WARN_COUNT++)); }
info() { echo -e "${CYAN}[INFO]${NC} $1"; }
section() { echo -e "\n${CYAN}========== $1 ==========${NC}\n"; }

# AWS-LOG-01: Check CloudTrail
check_cloudtrail() {
    section "AWS-LOG-01: CloudTrail Configuration"

    local trails=$(aws cloudtrail describe-trails --query 'trailList' --output json)

    if [[ $(echo "$trails" | jq 'length') -eq 0 ]]; then
        fail "No CloudTrail trails configured - CIS 3.1"
        return
    fi

    local multi_region_trail_exists=false

    for trail in $(echo "$trails" | jq -r '.[].TrailARN'); do
        local trail_name=$(echo "$trails" | jq -r ".[] | select(.TrailARN==\"$trail\") | .Name")
        local is_multi_region=$(echo "$trails" | jq -r ".[] | select(.TrailARN==\"$trail\") | .IsMultiRegionTrail")
        local log_validation=$(echo "$trails" | jq -r ".[] | select(.TrailARN==\"$trail\") | .LogFileValidationEnabled")

        # Check if multi-region
        if [[ "$is_multi_region" == "true" ]]; then
            pass "CloudTrail is multi-region: $trail_name - CIS 3.1"
            multi_region_trail_exists=true

            # Check log file validation
            if [[ "$log_validation" == "true" ]]; then
                pass "Log file validation enabled: $trail_name - CIS 3.2"
            else
                fail "Log file validation NOT enabled: $trail_name - CIS 3.2"
            fi

            # Check if trail is logging
            local status=$(aws cloudtrail get-trail-status --name "$trail_name" --query 'IsLogging' --output text)
            if [[ "$status" == "True" ]]; then
                pass "CloudTrail is actively logging: $trail_name"
            else
                fail "CloudTrail NOT logging: $trail_name"
            fi

            # Check S3 bucket not public
            local s3_bucket=$(echo "$trails" | jq -r ".[] | select(.TrailARN==\"$trail\") | .S3BucketName")
            local public_access=$(aws s3api get-public-access-block --bucket "$s3_bucket" 2>/dev/null || echo "")

            if [[ -n "$public_access" ]]; then
                pass "CloudTrail S3 bucket has public access block: $s3_bucket - CIS 3.3"
            else
                fail "CloudTrail S3 bucket lacks public access block: $s3_bucket - CIS 3.3"
            fi
        else
            warn "CloudTrail is NOT multi-region: $trail_name"
        fi
    done

    if [[ "$multi_region_trail_exists" == "false" ]]; then
        fail "No multi-region CloudTrail configured - CIS 3.1"
    fi
}

# AWS-LOG-02: Check AWS Config
check_aws_config() {
    section "AWS-LOG-02: AWS Config"

    local regions=$(aws ec2 describe-regions --query 'Regions[].RegionName' --output text)
    local config_enabled_count=0
    local total_regions=0

    for region in $regions; do
        ((total_regions++))
        local recorders=$(aws configservice describe-configuration-recorders --region "$region" --query 'ConfigurationRecorders' --output json 2>/dev/null || echo "[]")

        if [[ $(echo "$recorders" | jq 'length') -gt 0 ]]; then
            ((config_enabled_count++))
            pass "AWS Config enabled in region: $region - CIS 3.5"
        else
            fail "AWS Config NOT enabled in region: $region - CIS 3.5"
        fi
    done

    if [[ $config_enabled_count -eq $total_regions ]]; then
        pass "AWS Config enabled in all $total_regions regions"
    else
        fail "AWS Config only enabled in $config_enabled_count of $total_regions regions"
    fi
}

# AWS-LOG-03: Check GuardDuty
check_guardduty() {
    section "AWS-LOG-03: Amazon GuardDuty"

    local regions=$(aws ec2 describe-regions --query 'Regions[].RegionName' --output text)
    local guardduty_enabled_count=0
    local total_regions=0

    for region in $regions; do
        ((total_regions++))
        local detectors=$(aws guardduty list-detectors --region "$region" --query 'DetectorIds' --output text 2>/dev/null || echo "")

        if [[ -n "$detectors" ]]; then
            ((guardduty_enabled_count++))
            pass "GuardDuty enabled in region: $region - CIS 6.1"
        else
            fail "GuardDuty NOT enabled in region: $region - CIS 6.1"
        fi
    done

    if [[ $guardduty_enabled_count -eq $total_regions ]]; then
        pass "GuardDuty enabled in all $total_regions regions"
    else
        fail "GuardDuty only enabled in $guardduty_enabled_count of $total_regions regions"
    fi
}

# AWS-LOG-04: Check VPC Flow Logs
check_vpc_flow_logs() {
    section "AWS-LOG-04: VPC Flow Logs"

    local vpcs=$(aws ec2 describe-vpcs --query 'Vpcs[].VpcId' --output text)

    for vpc in $vpcs; do
        local flow_logs=$(aws ec2 describe-flow-logs --filter "Name=resource-id,Values=$vpc" --query 'FlowLogs' --output json)

        if [[ $(echo "$flow_logs" | jq 'length') -gt 0 ]]; then
            pass "VPC Flow Logs enabled for VPC: $vpc - CIS 3.9"
        else
            fail "VPC Flow Logs NOT enabled for VPC: $vpc - CIS 3.9"
        fi
    done
}

main() {
    echo -e "\n${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║   AWS Logging & Monitoring Security Checks                   ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}\n"

    check_cloudtrail
    check_aws_config
    check_guardduty
    check_vpc_flow_logs

    echo -e "\n${CYAN}=== Summary ===${NC}"
    echo -e "${GREEN}PASS: $PASS_COUNT${NC} | ${RED}FAIL: $FAIL_COUNT${NC} | ${YELLOW}WARN: $WARN_COUNT${NC}\n"

    [[ $FAIL_COUNT -gt 0 ]] && exit 1
    exit 0
}

main "$@"
