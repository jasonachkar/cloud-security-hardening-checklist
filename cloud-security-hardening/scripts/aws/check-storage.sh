#!/bin/bash
# AWS Storage Security Checks - CIS AWS Foundations Benchmark v3.0.0

set -euo pipefail
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
PASS_COUNT=0; FAIL_COUNT=0; WARN_COUNT=0

pass() { echo -e "${GREEN}[PASS]${NC} $1"; ((PASS_COUNT++)); }
fail() { echo -e "${RED}[FAIL]${NC} $1"; ((FAIL_COUNT++)); }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; ((WARN_COUNT++)); }
info() { echo -e "${CYAN}[INFO]${NC} $1"; }
section() { echo -e "\n${CYAN}========== $1 ==========${NC}\n"; }

# Check S3 buckets
check_s3_security() {
    section "AWS-STORAGE: S3 Bucket Security"

    local buckets=$(aws s3api list-buckets --query 'Buckets[].Name' --output text)

    for bucket in $buckets; do
        # Check encryption
        local encryption=$(aws s3api get-bucket-encryption --bucket "$bucket" 2>/dev/null || echo "")
        if [[ -n "$encryption" ]]; then
            pass "S3 bucket encrypted: $bucket - CIS 2.1.1"
        else
            fail "S3 bucket NOT encrypted: $bucket - CIS 2.1.1"
        fi

        # Check public access block
        local public_block=$(aws s3api get-public-access-block --bucket "$bucket" 2>/dev/null || echo "")
        if echo "$public_block" | jq -e '.PublicAccessBlockConfiguration | .BlockPublicAcls and .BlockPublicPolicy and .IgnorePublicAcls and .RestrictPublicBuckets' &>/dev/null; then
            pass "S3 bucket has public access blocked: $bucket - CIS 2.1.5"
        else
            fail "S3 bucket does NOT block public access: $bucket - CIS 2.1.5"
        fi

        # Check bucket policy for HTTPS enforcement
        local policy=$(aws s3api get-bucket-policy --bucket "$bucket" --query 'Policy' --output text 2>/dev/null || echo "")
        if echo "$policy" | jq -e '.Statement[] | select(.Effect=="Deny" and .Principal=="*" and .Condition.Bool."aws:SecureTransport"=="false")' &>/dev/null; then
            pass "S3 bucket enforces HTTPS: $bucket - CIS 2.1.2"
        else
            warn "S3 bucket may not enforce HTTPS: $bucket - CIS 2.1.2"
        fi
    done
}

# Check EBS encryption
check_ebs_encryption() {
    section "AWS-STORAGE: EBS Encryption"

    local ebs_default=$(aws ec2 get-ebs-encryption-by-default --query 'EbsEncryptionByDefault' --output text)

    if [[ "$ebs_default" == "True" ]]; then
        pass "EBS encryption enabled by default - CIS 2.2.1"
    else
        fail "EBS encryption NOT enabled by default - CIS 2.2.1"
    fi

    # Check individual volumes
    local volumes=$(aws ec2 describe-volumes --query 'Volumes[*].[VolumeId,Encrypted]' --output text)
    while read -r volume_id encrypted; do
        [[ -z "$volume_id" ]] && continue
        if [[ "$encrypted" == "True" ]]; then
            pass "EBS volume encrypted: $volume_id"
        else
            fail "EBS volume NOT encrypted: $volume_id"
        fi
    done <<< "$volumes"
}

# Check RDS encryption
check_rds_encryption() {
    section "AWS-STORAGE: RDS Encryption"

    local instances=$(aws rds describe-db-instances --query 'DBInstances[*].[DBInstanceIdentifier,StorageEncrypted,PubliclyAccessible]' --output text)

    while read -r db_id encrypted public; do
        [[ -z "$db_id" ]] && continue

        if [[ "$encrypted" == "True" ]]; then
            pass "RDS instance encrypted: $db_id - CIS 2.3.1"
        else
            fail "RDS instance NOT encrypted: $db_id - CIS 2.3.1"
        fi

        if [[ "$public" == "False" ]]; then
            pass "RDS instance not publicly accessible: $db_id - CIS 2.3.3"
        else
            fail "RDS instance is publicly accessible: $db_id - CIS 2.3.3"
        fi
    done <<< "$instances"
}

main() {
    echo -e "\n${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║   AWS Storage Security Checks                                 ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}\n"

    check_s3_security
    check_ebs_encryption
    check_rds_encryption

    echo -e "\n${CYAN}=== Summary ===${NC}"
    echo -e "${GREEN}PASS: $PASS_COUNT${NC} | ${RED}FAIL: $FAIL_COUNT${NC} | ${YELLOW}WARN: $WARN_COUNT${NC}\n"
    [[ $FAIL_COUNT -gt 0 ]] && exit 1
    exit 0
}

main "$@"
