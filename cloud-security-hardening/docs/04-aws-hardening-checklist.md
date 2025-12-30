# AWS Security Hardening Checklist

## Overview

This checklist provides comprehensive security hardening controls for Amazon Web Services (AWS) environments, aligned with CIS Amazon Web Services Foundations Benchmark v3.0.0. Each control includes verification methods, remediation guidance, and risk context.

## Control Format

Each control follows this structure:
- **Control ID**: Unique identifier (e.g., AWS-IAM-01)
- **CIS Reference**: CIS Benchmark control number
- **CIS Level**: 1 (foundational) or 2 (defense-in-depth)
- **Description**: What the control does
- **Security Impact**: Why this matters
- **Verification**: How to check manually
- **Automated Check**: Script reference
- **Remediation**: How to fix
- **Risk if Not Implemented**: Consequences of non-compliance

---

## Identity & Access Management (IAM)

### AWS-IAM-01: Enable MFA for Root Account

**CIS Reference**: 1.5, 1.6
**CIS Level**: 1

**Description**: Multi-factor authentication (MFA), preferably hardware MFA, must be enabled for the AWS root account.

**Security Impact**: Root account has unrestricted access to all AWS resources. Compromise of root credentials without MFA results in complete account takeover.

**Verification (Manual)**:
1. Log in to AWS Console as root user
2. Navigate to IAM > Security credentials
3. Verify MFA device is assigned and active
4. Preferably hardware MFA (U2F or hardware token)

**Automated Check**: `scripts/aws/check-iam.sh` (Function: check_root_mfa)

**Remediation**:
```bash
# Root MFA must be configured via AWS Console (cannot be automated)
# 1. Sign in as root user
# 2. Navigate to IAM > My Security Credentials
# 3. Click "Assign MFA device"
# 4. Choose Virtual MFA or Hardware MFA
# 5. Follow setup wizard to activate MFA

# Verify MFA is enabled
aws iam get-account-summary --query 'SummaryMap.AccountMFAEnabled'
```

**Risk if Not Implemented**:
- Complete account takeover from root credential compromise
- Unlimited access to all AWS resources
- Ability to delete all data and resources
- Potential for massive financial impact
- Compliance violations (CIS, PCI DSS, SOC 2)

---

### AWS-IAM-02: Remove Root Account Access Keys

**CIS Reference**: 1.7
**CIS Level**: 1

**Description**: The root account must not have programmatic access keys. Root access should only be via console with MFA.

**Security Impact**: Root access keys cannot be restricted by IAM policies and pose extreme risk if exposed.

**Verification (Manual)**:
1. Log in as root user
2. Navigate to IAM > My Security Credentials
3. Verify no access keys exist
4. Check "Access keys" section shows no active or inactive keys

**Automated Check**: `scripts/aws/check-iam.sh` (Function: check_root_access_keys)

**Remediation**:
```bash
# Root access key deletion must be done via Console
# 1. Sign in as root user
# 2. Navigate to IAM > My Security Credentials
# 3. Find Access Keys section
# 4. Delete all access keys (active and inactive)

# Verify no root access keys (returns 0 if no keys)
aws iam get-account-summary --query 'SummaryMap.AccountAccessKeysPresent'
```

**Risk if Not Implemented**:
- Root credentials in application code or scripts
- Accidental exposure in version control
- Programmatic access with no MFA protection
- Unlimited AWS API access if keys are compromised

---

### AWS-IAM-03: Eliminate Root User for Daily Tasks

**CIS Reference**: 1.8
**CIS Level**: 1

**Description**: Root account should not be used for daily administrative tasks. Create IAM admin users instead.

**Security Impact**: Using root account increases risk of accidental or malicious actions. IAM users provide better auditing and can be restricted.

**Verification (Manual)**:
1. Navigate to CloudTrail Event History
2. Filter for root user activity
3. Verify no root user events in past 30+ days
4. Check for userIdentity.type = "Root"

**Automated Check**: `scripts/aws/check-iam.sh` (Function: check_root_usage)

**Remediation**:
```bash
# Create IAM admin user instead of using root
aws iam create-user --user-name admin-user

# Attach AdministratorAccess policy
aws iam attach-user-policy --user-name admin-user \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Create console password with MFA requirement
aws iam create-login-profile --user-name admin-user \
  --password "InitialPassword123!" \
  --password-reset-required

# Create MFA device for admin user
aws iam create-virtual-mfa-device --virtual-mfa-device-name admin-mfa \
  --outfile QRCode.png --bootstrap-method QRCodePNG
```

**Risk if Not Implemented**:
- All actions logged as root (poor audit trail)
- Cannot apply least privilege
- No ability to restrict root actions
- Increased blast radius of mistakes

---

### AWS-IAM-04: Enforce Strong Password Policy

**CIS Reference**: 1.9, 1.10
**CIS Level**: 1

**Description**: IAM password policy must require minimum 14 characters, complexity requirements, password expiration, and prevent password reuse.

**Security Impact**: Strong passwords resist brute force attacks and credential stuffing.

**Verification (Manual)**:
1. Navigate to IAM > Account settings
2. Check password policy requirements:
   - Minimum length ≥ 14
   - Require uppercase, lowercase, numbers, symbols
   - Password expiration enabled
   - Prevent password reuse (5+ previous)
   - Allow users to change password

**Automated Check**: `scripts/aws/check-iam.sh` (Function: check_password_policy)

**Remediation**:
```bash
# Set strong IAM password policy
aws iam update-account-password-policy \
  --minimum-password-length 14 \
  --require-symbols \
  --require-numbers \
  --require-uppercase-characters \
  --require-lowercase-characters \
  --allow-users-to-change-password \
  --max-password-age 90 \
  --password-reuse-prevention 5 \
  --hard-expiry
```

**Risk if Not Implemented**:
- Weak passwords vulnerable to brute force
- Credential stuffing attacks succeed
- Long-lived credentials increase exposure
- Compliance violations

---

### AWS-IAM-05: Require MFA for All Console Users

**CIS Reference**: 1.11
**CIS Level**: 1

**Description**: Multi-factor authentication must be enabled for all IAM users with console access.

**Security Impact**: MFA prevents account takeover even if passwords are compromised through phishing or breaches.

**Verification (Manual)**:
1. Navigate to IAM > Users
2. Review MFA column
3. Verify all users with console access have MFA enabled
4. Check Credential Report for details

**Automated Check**: `scripts/aws/check-iam.sh` (Function: check_user_mfa)

**Remediation**:
```bash
# Enforce MFA via IAM policy
# Create policy that denies all actions except MFA management if MFA not present
cat > require-mfa-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyAllExceptListedIfNoMFA",
      "Effect": "Deny",
      "NotAction": [
        "iam:CreateVirtualMFADevice",
        "iam:EnableMFADevice",
        "iam:ListMFADevices",
        "iam:ListUsers",
        "iam:ListVirtualMFADevices",
        "iam:ResyncMFADevice",
        "sts:GetSessionToken"
      ],
      "Resource": "*",
      "Condition": {
        "BoolIfExists": {
          "aws:MultiFactorAuthPresent": "false"
        }
      }
    }
  ]
}
EOF

aws iam create-policy --policy-name RequireMFA \
  --policy-document file://require-mfa-policy.json

# Attach to all users or groups
aws iam attach-user-policy --user-name example-user \
  --policy-arn arn:aws:iam::ACCOUNT_ID:policy/RequireMFA
```

**Risk if Not Implemented**:
- Account takeover from phishing attacks
- Credential theft leads to immediate access
- No second factor protection
- Compliance violations

---

### AWS-IAM-06: Disable Unused Credentials

**CIS Reference**: 1.12, 1.13
**CIS Level**: 1

**Description**: IAM credentials unused for 45+ days must be disabled. Users should have only one active access key.

**Security Impact**: Old, forgotten credentials increase attack surface and are often not monitored.

**Verification (Manual)**:
1. Navigate to IAM > Credential Report
2. Download credential report
3. Review last_used dates for passwords and access keys
4. Identify credentials unused for 45+ days

**Automated Check**: `scripts/aws/check-iam.sh` (Function: check_unused_credentials)

**Remediation**:
```bash
# List users with credentials unused for 45+ days
aws iam get-credential-report --query 'Content' --output text | base64 -d > credential-report.csv

# Disable unused access keys (example)
aws iam update-access-key --access-key-id AKIAIOSFODNN7EXAMPLE \
  --status Inactive --user-name example-user

# Disable console access for unused accounts
aws iam delete-login-profile --user-name inactive-user
```

**Risk if Not Implemented**:
- Forgotten credentials not monitored
- Former employee access not revoked
- Stale credentials in compromised systems
- Expanded attack surface

---

### AWS-IAM-07: Rotate Access Keys Every 90 Days

**CIS Reference**: 1.14
**CIS Level**: 1

**Description**: IAM access keys must be rotated every 90 days or less.

**Security Impact**: Regular rotation limits the exposure window if keys are compromised.

**Verification (Manual)**:
1. Navigate to IAM > Users
2. Check access key age for each user
3. Verify no access keys older than 90 days
4. Review credential report

**Automated Check**: `scripts/aws/check-iam.sh` (Function: check_key_rotation)

**Remediation**:
```bash
# List access keys older than 90 days
aws iam list-access-keys --user-name example-user

# Create new access key
NEW_KEY=$(aws iam create-access-key --user-name example-user)

# Update applications to use new key
# (Application-specific process)

# Delete old access key
aws iam delete-access-key --user-name example-user \
  --access-key-id AKIAIOSFODNN7EXAMPLE

# Recommended: Automate with Lambda function
# Set CloudWatch Event to trigger monthly key rotation check
```

**Risk if Not Implemented**:
- Long-lived credentials more likely to be compromised
- Extended exposure if keys leaked
- No forcing function for credential refresh

---

### AWS-IAM-08: Avoid Wildcard Permissions in IAM Policies

**CIS Reference**: 1.16
**CIS Level**: 1

**Description**: IAM policies must not grant full administrative privileges (Effect: Allow, Action: *, Resource: *). Apply least privilege.

**Security Impact**: Overly permissive policies enable privilege escalation and lateral movement after initial compromise.

**Verification (Manual)**:
1. Navigate to IAM > Policies
2. Review customer-managed policies
3. Check for policies with Action: "*" and Resource: "*"
4. Review inline policies on users and roles

**Automated Check**: `scripts/aws/check-iam.sh` (Function: check_wildcard_policies)

**Remediation**:
```bash
# Review policies with wildcard permissions
aws iam list-policies --scope Local --query 'Policies[*].[PolicyName,Arn]' --output table

# Get policy version and review
aws iam get-policy-version --policy-arn arn:aws:iam::ACCOUNT_ID:policy/PolicyName \
  --version-id v1

# Replace with least privilege policy (example for EC2 admin)
cat > ec2-admin-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:*",
        "elasticloadbalancing:*",
        "autoscaling:*"
      ],
      "Resource": "*"
    }
  ]
}
EOF

# Update policy
aws iam create-policy-version --policy-arn arn:aws:iam::ACCOUNT_ID:policy/PolicyName \
  --policy-document file://ec2-admin-policy.json --set-as-default
```

**Risk if Not Implemented**:
- Privilege escalation attacks succeed
- Lateral movement across services
- Excessive blast radius of compromised accounts
- Violation of least privilege principle

---

## Logging & Monitoring

### AWS-LOG-01: Enable CloudTrail in All Regions

**CIS Reference**: 3.1, 3.2, 3.3, 3.4
**CIS Level**: 1

**Description**: CloudTrail must be enabled in all regions with log file validation, encrypted S3 storage, and CloudWatch Logs integration.

**Security Impact**: CloudTrail provides audit trail for all AWS API calls, essential for security investigations and compliance.

**Verification (Manual)**:
1. Navigate to CloudTrail > Trails
2. Verify at least one multi-region trail exists
3. Check trail is logging
4. Verify log file validation enabled
5. Confirm S3 bucket is not publicly accessible
6. Check CloudWatch Logs integration

**Automated Check**: `scripts/aws/check-logging.sh` (Function: check_cloudtrail)

**Remediation**:
```bash
# Create S3 bucket for CloudTrail logs
aws s3api create-bucket --bucket my-cloudtrail-logs-ACCOUNT_ID \
  --region us-east-1

# Apply bucket policy
cat > cloudtrail-bucket-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AWSCloudTrailAclCheck",
      "Effect": "Allow",
      "Principal": {"Service": "cloudtrail.amazonaws.com"},
      "Action": "s3:GetBucketAcl",
      "Resource": "arn:aws:s3:::my-cloudtrail-logs-ACCOUNT_ID"
    },
    {
      "Sid": "AWSCloudTrailWrite",
      "Effect": "Allow",
      "Principal": {"Service": "cloudtrail.amazonaws.com"},
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::my-cloudtrail-logs-ACCOUNT_ID/*",
      "Condition": {
        "StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}
      }
    }
  ]
}
EOF

aws s3api put-bucket-policy --bucket my-cloudtrail-logs-ACCOUNT_ID \
  --policy file://cloudtrail-bucket-policy.json

# Create CloudTrail trail
aws cloudtrail create-trail --name my-cloudtrail \
  --s3-bucket-name my-cloudtrail-logs-ACCOUNT_ID \
  --is-multi-region-trail \
  --enable-log-file-validation \
  --kms-key-id arn:aws:kms:us-east-1:ACCOUNT_ID:key/KEY_ID

# Start logging
aws cloudtrail start-logging --name my-cloudtrail

# Integrate with CloudWatch Logs
aws cloudtrail update-trail --name my-cloudtrail \
  --cloud-watch-logs-log-group-arn arn:aws:logs:us-east-1:ACCOUNT_ID:log-group:CloudTrail/logs \
  --cloud-watch-logs-role-arn arn:aws:iam::ACCOUNT_ID:role/CloudTrailRole
```

**Risk if Not Implemented**:
- No audit trail for security investigations
- Inability to detect unauthorized API calls
- Compliance violations (PCI DSS, HIPAA, SOX)
- Limited forensic capabilities
- Cannot detect or respond to threats

---

### AWS-LOG-02: Enable AWS Config in All Regions

**CIS Reference**: 3.5
**CIS Level**: 1

**Description**: AWS Config must be enabled in all regions to track resource configuration changes and compliance.

**Security Impact**: Config provides configuration history and change tracking, essential for detecting security drift.

**Verification (Manual)**:
1. Navigate to AWS Config console
2. Verify Config is enabled in all regions
3. Check configuration recorder is running
4. Verify delivery channel is configured

**Automated Check**: `scripts/aws/check-logging.sh` (Function: check_config)

**Remediation**:
```bash
# Create S3 bucket for Config
aws s3api create-bucket --bucket my-config-logs-ACCOUNT_ID \
  --region us-east-1

# Create IAM role for Config
aws iam create-role --role-name AWSConfigRole \
  --assume-role-policy-document file://config-trust-policy.json

aws iam attach-role-policy --role-name AWSConfigRole \
  --policy-arn arn:aws:iam::aws:policy/service-role/ConfigRole

# Enable AWS Config
aws configservice put-configuration-recorder \
  --configuration-recorder name=default,roleARN=arn:aws:iam::ACCOUNT_ID:role/AWSConfigRole \
  --recording-group allSupported=true,includeGlobalResourceTypes=true

aws configservice put-delivery-channel \
  --delivery-channel name=default,s3BucketName=my-config-logs-ACCOUNT_ID

# Start Config recorder
aws configservice start-configuration-recorder --configuration-recorder-name default
```

**Risk if Not Implemented**:
- No visibility into configuration changes
- Cannot detect security drift
- Inability to audit configuration history
- Compliance assessment gaps

---

### AWS-LOG-03: Enable GuardDuty

**CIS Reference**: 6.1
**CIS Level**: 1

**Description**: Amazon GuardDuty must be enabled for intelligent threat detection using machine learning.

**Security Impact**: GuardDuty provides automated threat detection for unauthorized and malicious activity.

**Verification (Manual)**:
1. Navigate to GuardDuty console
2. Verify GuardDuty is enabled
3. Check findings are being generated
4. Verify auto-enable for new accounts (if using Organizations)

**Automated Check**: `scripts/aws/check-logging.sh` (Function: check_guardduty)

**Remediation**:
```bash
# Enable GuardDuty
aws guardduty create-detector --enable

# Get detector ID
DETECTOR_ID=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)

# Verify enabled
aws guardduty get-detector --detector-id $DETECTOR_ID

# Optional: Enable for all accounts in organization
aws guardduty create-members --detector-id $DETECTOR_ID \
  --account-details AccountId=123456789012,Email=security@example.com
```

**Risk if Not Implemented**:
- No automated threat detection
- Manual log analysis required
- Delayed incident detection
- Missed security events

---

### AWS-LOG-04: Enable VPC Flow Logs

**CIS Reference**: 3.9
**CIS Level**: 2

**Description**: VPC Flow Logs must be enabled for all VPCs to capture network traffic metadata.

**Security Impact**: Flow logs enable detection of network-based attacks, data exfiltration, and lateral movement.

**Verification (Manual)**:
1. Navigate to VPC > Your VPCs
2. For each VPC, check Flow Logs tab
3. Verify flow logs are enabled
4. Check logs are sent to CloudWatch or S3

**Automated Check**: `scripts/aws/check-logging.sh` (Function: check_vpc_flow_logs)

**Remediation**:
```bash
# Create CloudWatch log group for VPC Flow Logs
aws logs create-log-group --log-group-name /aws/vpc/flowlogs

# Create IAM role for VPC Flow Logs
cat > vpc-flow-logs-trust-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {"Service": "vpc-flow-logs.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

aws iam create-role --role-name VPCFlowLogsRole \
  --assume-role-policy-document file://vpc-flow-logs-trust-policy.json

# Attach policy for CloudWatch Logs access
aws iam attach-role-policy --role-name VPCFlowLogsRole \
  --policy-arn arn:aws:iam::aws:policy/CloudWatchLogsFullAccess

# Enable VPC Flow Logs
VPC_ID=$(aws ec2 describe-vpcs --query 'Vpcs[0].VpcId' --output text)

aws ec2 create-flow-logs --resource-type VPC \
  --resource-ids $VPC_ID \
  --traffic-type ALL \
  --log-destination-type cloud-watch-logs \
  --log-group-name /aws/vpc/flowlogs \
  --iam-role-arn arn:aws:iam::ACCOUNT_ID:role/VPCFlowLogsRole
```

**Risk if Not Implemented**:
- No network traffic visibility
- Cannot detect lateral movement
- Limited forensic capabilities
- Delayed threat detection

---

## Network Security

### AWS-NET-01: Restrict Remote Server Administration Ports

**CIS Reference**: 5.1, 5.2
**CIS Level**: 1

**Description**: Security groups must not allow inbound SSH (22), RDP (3389), or other admin ports from 0.0.0.0/0.

**Security Impact**: Public exposure of admin ports enables brute force attacks and exploitation.

**Verification (Manual)**:
1. Navigate to EC2 > Security Groups
2. Review inbound rules
3. Verify no rules allow 0.0.0.0/0 access to ports 22, 3389, 3306, 1433, 5432

**Automated Check**: `scripts/aws/check-network.sh` (Function: check_security_group_rules)

**Remediation**:
```bash
# List security groups with public admin port access
aws ec2 describe-security-groups \
  --filters Name=ip-permission.from-port,Values=22 Name=ip-permission.cidr,Values='0.0.0.0/0'

# Remove overly permissive rule
aws ec2 revoke-security-group-ingress --group-id sg-12345678 \
  --protocol tcp --port 22 --cidr 0.0.0.0/0

# Add restricted rule (specific IP or VPN)
aws ec2 authorize-security-group-ingress --group-id sg-12345678 \
  --protocol tcp --port 22 --cidr YOUR_OFFICE_IP/32

# Recommended: Use AWS Systems Manager Session Manager instead
```

**Risk if Not Implemented**:
- SSH/RDP brute force attacks
- Exploitation of vulnerabilities
- Unauthorized access to instances
- Bot scanning and automated attacks

---

### AWS-NET-02: Restrict Default Security Groups

**CIS Reference**: 5.3
**CIS Level**: 1

**Description**: Default security groups must restrict all inbound and outbound traffic.

**Security Impact**: Default security groups are often forgotten and can provide unintended access.

**Verification (Manual)**:
1. Navigate to EC2 > Security Groups
2. Filter for default security groups
3. Verify no inbound or outbound rules exist

**Automated Check**: `scripts/aws/check-network.sh` (Function: check_default_security_groups)

**Remediation**:
```bash
# Remove all rules from default security group
DEFAULT_SG=$(aws ec2 describe-security-groups \
  --filters Name=group-name,Values=default \
  --query 'SecurityGroups[0].GroupId' --output text)

# Remove all inbound rules
aws ec2 revoke-security-group-ingress --group-id $DEFAULT_SG \
  --ip-permissions "$(aws ec2 describe-security-groups --group-ids $DEFAULT_SG \
    --query 'SecurityGroups[0].IpPermissions')"

# Remove all outbound rules
aws ec2 revoke-security-group-egress --group-id $DEFAULT_SG \
  --ip-permissions "$(aws ec2 describe-security-groups --group-ids $DEFAULT_SG \
    --query 'SecurityGroups[0].IpPermissionsEgress')"
```

**Risk if Not Implemented**:
- Unintended network access
- Resources accidentally using default SG
- Difficult to track security group usage

---

### AWS-NET-03: Use IMDSv2 for EC2 Metadata

**CIS Reference**: 5.6
**CIS Level**: 1

**Description**: EC2 instances must use Instance Metadata Service Version 2 (IMDSv2) to prevent SSRF attacks.

**Security Impact**: IMDSv2 requires session tokens, preventing SSRF attacks from stealing instance credentials.

**Verification (Manual)**:
1. Navigate to EC2 > Instances
2. Select instance > Actions > Instance Settings > Modify instance metadata options
3. Verify "IMDSv2" is required (not optional)

**Automated Check**: `scripts/aws/check-compute.sh` (Function: check_imdsv2)

**Remediation**:
```bash
# Require IMDSv2 for existing instance
aws ec2 modify-instance-metadata-options \
  --instance-id i-1234567890abcdef0 \
  --http-tokens required \
  --http-put-response-hop-limit 1

# Launch new instances with IMDSv2 required
aws ec2 run-instances --image-id ami-12345678 \
  --instance-type t3.micro \
  --metadata-options "HttpTokens=required,HttpPutResponseHopLimit=1"
```

**Risk if Not Implemented**:
- SSRF attacks can steal IAM credentials
- Potential for privilege escalation
- Instance credential theft

---

## Storage Security

### AWS-STORAGE-01: Block S3 Public Access

**CIS Reference**: 2.1.5
**CIS Level**: 1

**Description**: S3 Block Public Access must be enabled at account and bucket levels to prevent accidental public exposure.

**Security Impact**: Public S3 buckets are a leading cause of data breaches.

**Verification (Manual)**:
1. Navigate to S3 > Block Public Access settings
2. Verify all four settings enabled at account level
3. Check individual buckets have Block Public Access enabled

**Automated Check**: `scripts/aws/check-storage.sh` (Function: check_s3_public_access)

**Remediation**:
```bash
# Enable S3 Block Public Access at account level
aws s3control put-public-access-block \
  --account-id ACCOUNT_ID \
  --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

# Enable for specific bucket
aws s3api put-public-access-block --bucket my-bucket \
  --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
```

**Risk if Not Implemented**:
- Accidental public data exposure
- Data breaches
- Sensitive information leakage
- Compliance violations

---

### AWS-STORAGE-02: Enable S3 Encryption at Rest

**CIS Reference**: 2.1.1
**CIS Level**: 1

**Description**: All S3 buckets must have encryption at rest enabled using SSE-S3, SSE-KMS, or SSE-C.

**Security Impact**: Encryption protects data confidentiality if storage media is compromised.

**Verification (Manual)**:
1. Navigate to S3 > Buckets
2. Select bucket > Properties > Default encryption
3. Verify encryption is enabled

**Automated Check**: `scripts/aws/check-storage.sh` (Function: check_s3_encryption)

**Remediation**:
```bash
# Enable default encryption for S3 bucket (SSE-S3)
aws s3api put-bucket-encryption --bucket my-bucket \
  --server-side-encryption-configuration '{
    "Rules": [{
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "AES256"
      },
      "BucketKeyEnabled": true
    }]
  }'

# Or use KMS encryption (recommended)
aws s3api put-bucket-encryption --bucket my-bucket \
  --server-side-encryption-configuration '{
    "Rules": [{
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "aws:kms",
        "KMSMasterKeyID": "arn:aws:kms:us-east-1:ACCOUNT_ID:key/KEY_ID"
      },
      "BucketKeyEnabled": true
    }]
  }'
```

**Risk if Not Implemented**:
- Data exposure if storage compromised
- Compliance violations
- Inability to meet data protection requirements

---

### AWS-STORAGE-03: Enable EBS Encryption by Default

**CIS Reference**: 2.2.1
**CIS Level**: 2

**Description**: EBS encryption must be enabled by default for all new volumes in all regions.

**Security Impact**: Ensures all EBS volumes are encrypted, preventing unencrypted data at rest.

**Verification (Manual)**:
1. Navigate to EC2 > EBS > Account Attributes
2. Check "Always encrypt new EBS volumes" for each region
3. Verify setting is enabled

**Automated Check**: `scripts/aws/check-storage.sh` (Function: check_ebs_encryption)

**Remediation**:
```bash
# Enable EBS encryption by default (per region)
aws ec2 enable-ebs-encryption-by-default --region us-east-1

# Verify enabled
aws ec2 get-ebs-encryption-by-default --region us-east-1

# Repeat for all regions
for region in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  echo "Enabling EBS encryption in $region"
  aws ec2 enable-ebs-encryption-by-default --region $region
done
```

**Risk if Not Implemented**:
- Unencrypted EBS volumes created
- Data exposure risk
- Manual encryption required

---

### AWS-STORAGE-04: Enable RDS Encryption

**CIS Reference**: 2.3.1
**CIS Level**: 1

**Description**: RDS instances must have encryption at rest enabled using KMS.

**Security Impact**: Database encryption protects sensitive data from unauthorized access.

**Verification (Manual)**:
1. Navigate to RDS > Databases
2. Select each instance
3. Check Configuration > Encryption > Enabled

**Automated Check**: `scripts/aws/check-storage.sh` (Function: check_rds_encryption)

**Remediation**:
```bash
# Enable encryption for new RDS instance
aws rds create-db-instance --db-instance-identifier mydb \
  --engine mysql \
  --db-instance-class db.t3.micro \
  --allocated-storage 20 \
  --master-username admin \
  --master-user-password MyPassword123 \
  --storage-encrypted \
  --kms-key-id arn:aws:kms:us-east-1:ACCOUNT_ID:key/KEY_ID

# For existing unencrypted RDS:
# 1. Create snapshot
# 2. Copy snapshot with encryption enabled
# 3. Restore from encrypted snapshot
# 4. Update application connection strings

aws rds create-db-snapshot --db-instance-identifier mydb \
  --db-snapshot-identifier mydb-snapshot

aws rds copy-db-snapshot --source-db-snapshot-identifier mydb-snapshot \
  --target-db-snapshot-identifier mydb-snapshot-encrypted \
  --kms-key-id arn:aws:kms:us-east-1:ACCOUNT_ID:key/KEY_ID

aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier mydb-encrypted \
  --db-snapshot-identifier mydb-snapshot-encrypted
```

**Risk if Not Implemented**:
- Database data exposure
- Compliance violations (PCI DSS, HIPAA)
- Unprotected sensitive information

---

## Compute Security

### AWS-COMPUTE-01: Ensure EC2 Instances Use Approved AMIs

**CIS Reference**: Custom (Best Practice)
**CIS Level**: 2

**Description**: EC2 instances should be launched from organization-approved AMIs with security baselines.

**Security Impact**: Unapproved AMIs may contain malware, backdoors, or misconfigurations.

**Verification (Manual)**:
1. Navigate to EC2 > Instances
2. Check AMI ID for each instance
3. Verify against approved AMI list
4. Use AWS Config rule: approved-amis-by-id

**Automated Check**: `scripts/aws/check-compute.sh` (Function: check_approved_amis)

**Remediation**:
```bash
# Create AWS Config rule for approved AMIs
aws configservice put-config-rule --config-rule '{
  "ConfigRuleName": "approved-amis-by-id",
  "Source": {
    "Owner": "AWS",
    "SourceIdentifier": "APPROVED_AMIS_BY_ID"
  },
  "InputParameters": "{\"amiIds\":\"ami-12345678,ami-87654321\"}",
  "Scope": {
    "ComplianceResourceTypes": ["AWS::EC2::Instance"]
  }
}'

# Terminate non-compliant instances and relaunch with approved AMIs
```

**Risk if Not Implemented**:
- Malware in base images
- Inconsistent security baselines
- Unknown backdoors or vulnerabilities

---

## Summary Checklist

Use this quick reference for assessment tracking:

### Identity & Access Management
- [ ] AWS-IAM-01: Root account MFA enabled
- [ ] AWS-IAM-02: Root account has no access keys
- [ ] AWS-IAM-03: Root user not used for daily tasks
- [ ] AWS-IAM-04: Strong password policy enforced
- [ ] AWS-IAM-05: MFA required for console users
- [ ] AWS-IAM-06: Unused credentials disabled (45+ days)
- [ ] AWS-IAM-07: Access keys rotated every 90 days
- [ ] AWS-IAM-08: No wildcard IAM permissions

### Logging & Monitoring
- [ ] AWS-LOG-01: CloudTrail enabled in all regions
- [ ] AWS-LOG-02: AWS Config enabled
- [ ] AWS-LOG-03: GuardDuty enabled
- [ ] AWS-LOG-04: VPC Flow Logs enabled

### Network Security
- [ ] AWS-NET-01: Admin ports not open to 0.0.0.0/0
- [ ] AWS-NET-02: Default security groups restrict all traffic
- [ ] AWS-NET-03: IMDSv2 required for EC2 instances

### Storage Security
- [ ] AWS-STORAGE-01: S3 Block Public Access enabled
- [ ] AWS-STORAGE-02: S3 encryption at rest enabled
- [ ] AWS-STORAGE-03: EBS encryption enabled by default
- [ ] AWS-STORAGE-04: RDS encryption enabled

### Compute Security
- [ ] AWS-COMPUTE-01: EC2 instances use approved AMIs

---

**Next**: Review [05-remediation-guide.md](05-remediation-guide.md) for detailed fix procedures.
