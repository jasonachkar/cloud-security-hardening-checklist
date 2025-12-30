# Security Remediation Guide

## Overview

This guide provides detailed, step-by-step remediation procedures for failed security controls. Each remediation includes prerequisites, estimated effort, potential impact, and rollback procedures.

## Using This Guide

**Before Remediating**:
1. Review the security control and understand the risk
2. Check prerequisites and required permissions
3. Assess business impact and schedule maintenance if needed
4. Test in non-production environment first
5. Document changes and notify stakeholders
6. Have rollback plan ready

**Remediation Priority**:
- **Critical**: MFA, logging, public access exposure - remediate immediately
- **High**: Encryption, network security - remediate within 7 days
- **Medium**: Configuration optimization - remediate within 30 days
- **Low**: Best practice improvements - planned implementation

---

## Azure Remediation Procedures

### IAM-01: Enable MFA for Privileged Accounts

**Prerequisites**:
- Global Administrator or Security Administrator role
- Microsoft Authenticator app or hardware token
- Each user's mobile device or email for MFA registration

**Impact**: Users will need to enroll in MFA; may cause brief login delays

**Estimated Time**: 15 minutes per user

**Remediation Steps**:

**Option 1: Conditional Access Policy (Recommended)**

```powershell
# Install required module
Install-Module Microsoft.Graph -Scope CurrentUser

# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess"

# Create Conditional Access policy for MFA
$conditions = @{
    Users = @{
        IncludeRoles = @(
            "62e90394-69f5-4237-9190-012177145e10", # Global Administrator
            "194ae4cb-b126-40b2-bd5b-6091b380977d", # Security Administrator
            "f28a1f50-f6e7-4571-818b-6a12f2af6b6c"  # Privileged Role Administrator
        )
    }
    Applications = @{
        IncludeApplications = @("All")
    }
}

$grantControls = @{
    Operator = "AND"
    BuiltInControls = @("mfa")
}

$policy = @{
    DisplayName = "Require MFA for Privileged Roles"
    State = "enabled"
    Conditions = $conditions
    GrantControls = $grantControls
}

New-MgIdentityConditionalAccessPolicy -BodyParameter $policy
```

**Option 2: Per-User MFA (Azure AD Free)**

1. Navigate to Azure Portal > Microsoft Entra ID
2. Go to Users > All users
3. Click "Per-user MFA" at the top
4. Select privileged users
5. Click "Enable" under Quick steps
6. Confirm enablement

**Verification**:
```powershell
# Verify Conditional Access policy exists
Get-MgIdentityConditionalAccessPolicy | Where-Object {$_.DisplayName -eq "Require MFA for Privileged Roles"}

# Check MFA status for users
Connect-MsolService
Get-MsolUser -All | Select-Object UserPrincipalName, StrongAuthenticationRequirements
```

**Rollback**:
```powershell
# Disable Conditional Access policy
$policy = Get-MgIdentityConditionalAccessPolicy | Where-Object {$_.DisplayName -eq "Require MFA for Privileged Roles"}
Update-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $policy.Id -State "disabled"
```

**User Impact**: Users will be prompted to set up MFA on next login. Provide user communication template:

```
Subject: Action Required: Multi-Factor Authentication Enrollment

Dear [User],

As part of our ongoing security improvements, Multi-Factor Authentication (MFA)
is now required for your account. You will be prompted to set up MFA the next
time you sign in.

What you need:
- Your mobile phone
- Microsoft Authenticator app (recommended) or phone number for SMS

Setup takes approximately 5 minutes. Instructions: [link to MFA guide]

Questions? Contact IT Security: security@company.com

Thank you for helping keep our systems secure.
```

---

### STORAGE-01: Disable Public Blob Access

**Prerequisites**:
- Storage Account Contributor or Owner role
- Verification that no legitimate public access scenarios exist

**Impact**: Publicly accessible blobs will become inaccessible; applications using public URLs will break

**Estimated Time**: 5 minutes per storage account

**Pre-Remediation Assessment**:

```powershell
# Identify storage accounts with public access enabled
$subscriptions = Get-AzSubscription

foreach ($sub in $subscriptions) {
    Set-AzContext -SubscriptionId $sub.Id

    $storageAccounts = Get-AzStorageAccount

    foreach ($sa in $storageAccounts) {
        $allowPublic = $sa.AllowBlobPublicAccess

        if ($allowPublic) {
            Write-Host "WARN: $($sa.StorageAccountName) allows public blob access" -ForegroundColor Yellow

            # Check if any containers actually have public access
            $ctx = $sa.Context
            $containers = Get-AzStorageContainer -Context $ctx

            foreach ($container in $containers) {
                if ($container.PublicAccess -ne "Off") {
                    Write-Host "  Container: $($container.Name) - Public Access: $($container.PublicAccess)" -ForegroundColor Red
                }
            }
        }
    }
}
```

**Remediation Steps**:

```powershell
# Step 1: Identify dependent applications (CRITICAL)
# Review application logs and configurations for storage account URLs
# Identify if any apps use public blob URLs (no SAS token in URL)

# Step 2: Implement alternative access (if public access is needed)
# Option A: Use Shared Access Signatures (SAS)
$ctx = (Get-AzStorageAccount -ResourceGroupName "MyRG" -Name "mystorageaccount").Context

# Generate SAS token for specific container
$sasToken = New-AzStorageContainerSASToken -Context $ctx `
    -Name "public-container" `
    -Permission rl `
    -ExpiryTime (Get-Date).AddYears(1)

Write-Host "SAS URL: https://mystorageaccount.blob.core.windows.net/public-container$sasToken"

# Option B: Use Azure CDN with private blob access
# Option C: Use Azure Front Door with private endpoints

# Step 3: Update applications to use SAS tokens or private access

# Step 4: Disable public access at container level first (staged approach)
$containers = Get-AzStorageContainer -Context $ctx
foreach ($container in $containers) {
    if ($container.PublicAccess -ne "Off") {
        Set-AzStorageContainerAcl -Name $container.Name -Context $ctx -Permission Off
        Write-Host "Disabled public access for container: $($container.Name)"
    }
}

# Step 5: Wait 24-48 hours and monitor for broken applications

# Step 6: Disable public access at storage account level
Set-AzStorageAccount -ResourceGroupName "MyRG" `
    -Name "mystorageaccount" `
    -AllowBlobPublicAccess $false

Write-Host "Public blob access disabled at account level"
```

**Verification**:
```powershell
# Verify public access is disabled
$sa = Get-AzStorageAccount -ResourceGroupName "MyRG" -Name "mystorageaccount"
if ($sa.AllowBlobPublicAccess -eq $false) {
    Write-Host "PASS: Public blob access is disabled" -ForegroundColor Green
} else {
    Write-Host "FAIL: Public blob access is still enabled" -ForegroundColor Red
}

# Test public URL access (should fail)
$testUrl = "https://mystorageaccount.blob.core.windows.net/container/file.txt"
try {
    Invoke-WebRequest -Uri $testUrl -ErrorAction Stop
    Write-Host "FAIL: Public access still works" -ForegroundColor Red
} catch {
    Write-Host "PASS: Public access blocked as expected" -ForegroundColor Green
}
```

**Rollback**:
```powershell
# Re-enable public blob access (temporary only)
Set-AzStorageAccount -ResourceGroupName "MyRG" `
    -Name "mystorageaccount" `
    -AllowBlobPublicAccess $true

# Re-enable at container level
Set-AzStorageContainerAcl -Name "container-name" -Context $ctx -Permission Container
```

---

### LOG-01: Configure Activity Log Retention

**Prerequisites**:
- Log Analytics Workspace already created
- Subscription Owner or Monitoring Contributor role
- Storage account (optional, for long-term archival)

**Impact**: Minimal - improves audit capabilities

**Estimated Time**: 10 minutes

**Remediation Steps**:

```powershell
# Step 1: Create Log Analytics Workspace (if not exists)
$workspace = New-AzOperationalInsightsWorkspace `
    -ResourceGroupName "monitoring-rg" `
    -Name "central-logs-workspace" `
    -Location "eastus" `
    -Sku "PerGB2018" `
    -RetentionInDays 365

# Step 2: Configure diagnostic settings for Activity Log
$subscriptionId = (Get-AzContext).Subscription.Id

$logCategories = @(
    "Administrative",
    "Security",
    "ServiceHealth",
    "Alert",
    "Recommendation",
    "Policy",
    "Autoscale",
    "ResourceHealth"
)

$logs = @()
foreach ($category in $logCategories) {
    $logs += @{
        Category = $category
        Enabled = $true
        RetentionPolicy = @{
            Enabled = $true
            Days = 365
        }
    }
}

# Create diagnostic setting
$setting = @{
    Name = "ActivityLogs-to-LogAnalytics"
    WorkspaceId = $workspace.ResourceId
    Log = $logs
}

Set-AzDiagnosticSetting -ResourceId "/subscriptions/$subscriptionId" `
    -WorkspaceId $workspace.ResourceId `
    -Enabled $true `
    -Log $logs `
    -Name "ActivityLogs-to-LogAnalytics"

Write-Host "Activity Log diagnostic setting configured"

# Step 3: Optionally export to Storage Account for cheaper long-term retention
$storageAccount = Get-AzStorageAccount -ResourceGroupName "monitoring-rg" -Name "auditlogs"

Set-AzDiagnosticSetting -ResourceId "/subscriptions/$subscriptionId" `
    -StorageAccountId $storageAccount.Id `
    -Enabled $true `
    -Log $logs `
    -RetentionInDays 2555 `  # 7 years for compliance
    -Name "ActivityLogs-to-Storage"
```

**Verification**:
```powershell
# Check diagnostic settings
$diagnostics = Get-AzDiagnosticSetting -ResourceId "/subscriptions/$subscriptionId"

foreach ($diag in $diagnostics) {
    Write-Host "Diagnostic Setting: $($diag.Name)"
    Write-Host "  Workspace: $($diag.WorkspaceId)"
    Write-Host "  Categories: $($diag.Log.Category -join ', ')"

    # Verify retention
    foreach ($log in $diag.Log) {
        if ($log.RetentionPolicy.Days -ge 365) {
            Write-Host "  PASS: $($log.Category) retention = $($log.RetentionPolicy.Days) days" -ForegroundColor Green
        } else {
            Write-Host "  FAIL: $($log.Category) retention = $($log.RetentionPolicy.Days) days" -ForegroundColor Red
        }
    }
}

# Query logs to verify ingestion
$query = @"
AzureActivity
| where TimeGenerated > ago(1h)
| summarize count() by CategoryValue
"@

Invoke-AzOperationalInsightsQuery -WorkspaceId $workspace.CustomerId -Query $query
```

---

## AWS Remediation Procedures

### IAM-01: Enable Root Account MFA

**Prerequisites**:
- Root account credentials
- MFA device (virtual app or hardware token)
- Secure storage for backup codes

**Impact**: Adds security layer to root account; no functional impact

**Estimated Time**: 10 minutes

**Remediation Steps**:

**Important**: Root MFA MUST be configured through AWS Console (cannot be automated)

1. **Sign in as root user**:
   - Go to AWS Console
   - Use root email and password
   - Click "Sign in"

2. **Navigate to MFA settings**:
   - Click on account name (top right) > "Security Credentials"
   - Find "Multi-factor authentication (MFA)" section
   - Click "Assign MFA device"

3. **Choose MFA device type**:
   - **Virtual MFA** (recommended for most users):
     - Select "Virtual MFA device"
     - Install authenticator app (Authy, Google Authenticator, Microsoft Authenticator)
     - Scan QR code
     - Enter two consecutive codes

   - **Hardware MFA** (recommended for highly sensitive environments):
     - Select "Hardware TOTP token"
     - Enter device serial number
     - Enter two consecutive codes from device

4. **Save backup codes**:
   - Download and securely store backup codes
   - Store in password manager or encrypted vault
   - Consider printing and storing in safe

5. **Test MFA**:
   - Sign out
   - Sign back in as root
   - Verify MFA prompt appears
   - Enter MFA code successfully

**Verification**:
```bash
# Verify root MFA is enabled
aws iam get-account-summary --query 'SummaryMap.AccountMFAEnabled' --output text

# Expected output: 1 (enabled)
# If output is 0, MFA is not enabled
```

**Post-Configuration**:

```bash
# Document MFA device serial number (for recovery)
aws iam list-virtual-mfa-devices --assignment-status Assigned --query 'VirtualMFADevices[?User.Arn==`arn:aws:iam::ACCOUNT_ID:root`].SerialNumber'

# Create CloudWatch alarm for root usage
aws cloudwatch put-metric-alarm \
  --alarm-name "RootAccountUsage" \
  --alarm-description "Alert when root account is used" \
  --metric-name "RootAccountUsage" \
  --namespace "CloudTrailMetrics" \
  --statistic Sum \
  --period 300 \
  --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --evaluation-periods 1 \
  --alarm-actions arn:aws:sns:us-east-1:ACCOUNT_ID:security-alerts
```

**MFA Recovery Procedure** (if device is lost):

1. Sign in to AWS Console as root
2. Click "Trouble signing in?"
3. Select "Lost or not working MFA device"
4. Complete account verification (email, phone, payment method)
5. AWS Support will remove old MFA device
6. Assign new MFA device immediately

---

### STORAGE-01: Enable S3 Block Public Access

**Prerequisites**:
- S3 administrator permissions
- Verification that no buckets require public access
- Application impact assessment

**Impact**: Publicly accessible S3 buckets will become private; public URLs will stop working

**Estimated Time**: 5 minutes for configuration, up to 1 day for application testing

**Pre-Remediation Assessment**:

```bash
# Identify buckets with public access
echo "Checking all S3 buckets for public access..."

for bucket in $(aws s3api list-buckets --query 'Buckets[].Name' --output text); do
    echo "Checking bucket: $bucket"

    # Check bucket policy for public access
    policy=$(aws s3api get-bucket-policy --bucket $bucket 2>/dev/null)
    if echo "$policy" | grep -q "Principal.*\*"; then
        echo "  WARNING: Bucket policy allows public access"
    fi

    # Check ACL for public access
    acl=$(aws s3api get-bucket-acl --bucket $bucket --query 'Grants[?Grantee.URI==`http://acs.amazonaws.com/groups/global/AllUsers`]' --output text)
    if [ -n "$acl" ]; then
        echo "  WARNING: ACL grants public access"
    fi

    # Check public access block configuration
    block=$(aws s3api get-public-access-block --bucket $bucket 2>/dev/null)
    if [ -z "$block" ]; then
        echo "  FAIL: No public access block configured"
    fi
done
```

**Remediation Steps**:

**Step 1: Enable at Account Level (Recommended)**

```bash
# Enable S3 Block Public Access for entire AWS account
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

aws s3control put-public-access-block \
  --account-id $ACCOUNT_ID \
  --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

echo "S3 Block Public Access enabled at account level"
```

**Step 2: Enable at Bucket Level (Granular Control)**

```bash
# Enable for specific bucket
BUCKET_NAME="my-bucket"

aws s3api put-public-access-block \
  --bucket $BUCKET_NAME \
  --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

echo "Public access blocked for bucket: $BUCKET_NAME"

# Enable for all buckets
for bucket in $(aws s3api list-buckets --query 'Buckets[].Name' --output text); do
    echo "Blocking public access for: $bucket"
    aws s3api put-public-access-block --bucket $bucket \
      --public-access-block-configuration \
        BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true || echo "  Failed (may already be blocked)"
done
```

**Step 3: Implement Alternatives for Legitimate Public Access**

If public access is truly needed:

```bash
# Option A: Use CloudFront with Origin Access Identity (OAI)
# 1. Create CloudFront OAI
OAI_ID=$(aws cloudfront create-cloud-front-origin-access-identity \
  --cloud-front-origin-access-identity-config \
    CallerReference=$(date +%s),Comment="OAI for my-bucket" \
  --query 'CloudFrontOriginAccessIdentity.Id' --output text)

# 2. Update S3 bucket policy to allow CloudFront OAI
cat > bucket-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "AllowCloudFrontOAI",
    "Effect": "Allow",
    "Principal": {
      "AWS": "arn:aws:iam::cloudfront:user/CloudFront Origin Access Identity $OAI_ID"
    },
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::$BUCKET_NAME/*"
  }]
}
EOF

aws s3api put-bucket-policy --bucket $BUCKET_NAME --policy file://bucket-policy.json

# Option B: Use presigned URLs for temporary access
# Generate presigned URL (valid for 1 hour)
aws s3 presign s3://$BUCKET_NAME/object-key --expires-in 3600
```

**Verification**:

```bash
# Verify account-level block
aws s3control get-public-access-block --account-id $ACCOUNT_ID

# Expected output:
# {
#     "PublicAccessBlockConfiguration": {
#         "BlockPublicAcls": true,
#         "IgnorePublicAcls": true,
#         "BlockPublicPolicy": true,
#         "RestrictPublicBuckets": true
#     }
# }

# Verify bucket-level block
aws s3api get-public-access-block --bucket $BUCKET_NAME

# Test public access (should fail)
curl -I https://$BUCKET_NAME.s3.amazonaws.com/test-file.txt
# Expected: HTTP 403 Forbidden
```

**Rollback** (only if absolutely necessary):

```bash
# Disable block at account level
aws s3control delete-public-access-block --account-id $ACCOUNT_ID

# Disable block at bucket level
aws s3api delete-public-access-block --bucket $BUCKET_NAME
```

---

### LOG-01: Enable CloudTrail in All Regions

**Prerequisites**:
- S3 bucket for CloudTrail logs (separate from application buckets)
- KMS key for log encryption (recommended)
- CloudWatch Logs group (for real-time monitoring)
- Appropriate IAM permissions

**Impact**: Minimal performance impact; adds AWS costs for S3 storage and CloudWatch Logs

**Estimated Time**: 20 minutes

**Cost Estimate**:
- CloudTrail: First trail free, additional trails $2/100,000 events
- S3 Storage: ~$0.023/GB/month
- CloudWatch Logs: $0.50/GB ingested, $0.03/GB stored

**Remediation Steps**:

**Step 1: Create S3 Bucket for CloudTrail**

```bash
# Create dedicated S3 bucket
BUCKET_NAME="cloudtrail-logs-$(aws sts get-caller-identity --query Account --output text)"
REGION="us-east-1"

aws s3api create-bucket --bucket $BUCKET_NAME --region $REGION

# Block public access
aws s3api put-public-access-block --bucket $BUCKET_NAME \
  --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

# Create bucket policy for CloudTrail
cat > cloudtrail-bucket-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AWSCloudTrailAclCheck",
      "Effect": "Allow",
      "Principal": {"Service": "cloudtrail.amazonaws.com"},
      "Action": "s3:GetBucketAcl",
      "Resource": "arn:aws:s3:::$BUCKET_NAME"
    },
    {
      "Sid": "AWSCloudTrailWrite",
      "Effect": "Allow",
      "Principal": {"Service": "cloudtrail.amazonaws.com"},
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::$BUCKET_NAME/AWSLogs/*",
      "Condition": {
        "StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}
      }
    }
  ]
}
EOF

aws s3api put-bucket-policy --bucket $BUCKET_NAME --policy file://cloudtrail-bucket-policy.json

# Enable versioning
aws s3api put-bucket-versioning --bucket $BUCKET_NAME \
  --versioning-configuration Status=Enabled

# Set lifecycle policy for cost optimization
cat > lifecycle-policy.json << EOF
{
  "Rules": [{
    "Id": "ArchiveOldLogs",
    "Status": "Enabled",
    "Transitions": [
      {
        "Days": 90,
        "StorageClass": "STANDARD_IA"
      },
      {
        "Days": 365,
        "StorageClass": "GLACIER"
      }
    ],
    "Expiration": {
      "Days": 2555
    }
  }]
}
EOF

aws s3api put-bucket-lifecycle-configuration --bucket $BUCKET_NAME \
  --lifecycle-configuration file://lifecycle-policy.json
```

**Step 2: Create KMS Key for Encryption**

```bash
# Create KMS key for CloudTrail encryption
KEY_ID=$(aws kms create-key --description "CloudTrail log encryption" \
  --query 'KeyMetadata.KeyId' --output text)

# Create alias
aws kms create-alias --alias-name alias/cloudtrail --target-key-id $KEY_ID

# Update key policy to allow CloudTrail
cat > kms-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Enable IAM User Permissions",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::ACCOUNT_ID:root"},
      "Action": "kms:*",
      "Resource": "*"
    },
    {
      "Sid": "Allow CloudTrail to encrypt logs",
      "Effect": "Allow",
      "Principal": {"Service": "cloudtrail.amazonaws.com"},
      "Action": ["kms:GenerateDataKey*", "kms:DecryptDataKey"],
      "Resource": "*",
      "Condition": {
        "StringLike": {
          "kms:EncryptionContext:aws:cloudtrail:arn": "arn:aws:cloudtrail:*:ACCOUNT_ID:trail/*"
        }
      }
    }
  ]
}
EOF

# Apply policy
aws kms put-key-policy --key-id $KEY_ID --policy-name default --policy file://kms-policy.json
```

**Step 3: Create CloudWatch Logs Group**

```bash
# Create log group
aws logs create-log-group --log-group-name /aws/cloudtrail/logs

# Set retention
aws logs put-retention-policy --log-group-name /aws/cloudtrail/logs --retention-in-days 365

# Create IAM role for CloudTrail to CloudWatch Logs
cat > cloudtrail-assume-role-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "cloudtrail.amazonaws.com"},
    "Action": "sts:AssumeRole"
  }]
}
EOF

ROLE_ARN=$(aws iam create-role --role-name CloudTrailToCloudWatchLogs \
  --assume-role-policy-document file://cloudtrail-assume-role-policy.json \
  --query 'Role.Arn' --output text)

# Attach policy
cat > cloudtrail-cloudwatch-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
    "Resource": "arn:aws:logs:*:*:log-group:/aws/cloudtrail/logs:*"
  }]
}
EOF

aws iam put-role-policy --role-name CloudTrailToCloudWatchLogs \
  --policy-name CloudWatchLogsPolicy \
  --policy-document file://cloudtrail-cloudwatch-policy.json
```

**Step 4: Create Multi-Region CloudTrail**

```bash
# Create CloudTrail trail
aws cloudtrail create-trail \
  --name organization-trail \
  --s3-bucket-name $BUCKET_NAME \
  --is-multi-region-trail \
  --enable-log-file-validation \
  --kms-key-id $KEY_ID \
  --cloud-watch-logs-log-group-arn arn:aws:logs:us-east-1:ACCOUNT_ID:log-group:/aws/cloudtrail/logs:* \
  --cloud-watch-logs-role-arn $ROLE_ARN \
  --include-global-service-events

# Start logging
aws cloudtrail start-logging --name organization-trail

# Enable insights (optional but recommended)
aws cloudtrail put-insight-selectors --trail-name organization-trail \
  --insight-selectors '[{"InsightType": "ApiCallRateInsight"}]'
```

**Verification**:

```bash
# Verify trail status
aws cloudtrail get-trail-status --name organization-trail

# Expected output:
# {
#     "IsLogging": true,
#     "LatestDeliveryTime": <timestamp>,
#     "StartLoggingTime": <timestamp>
# }

# Verify trail configuration
aws cloudtrail describe-trails --trail-name-list organization-trail

# Check that logs are being delivered
aws s3 ls s3://$BUCKET_NAME/AWSLogs/

# Verify CloudWatch Logs ingestion
aws logs describe-log-streams --log-group-name /aws/cloudtrail/logs --max-items 5
```

---

## Remediation Best Practices

### 1. Test in Non-Production First

Always test remediation procedures in development or staging environments before production:

```bash
# Use AWS Organizations test account
aws organizations list-accounts --query 'Accounts[?Name==`dev`].Id' --output text

# Or create isolated test environment
```

### 2. Implement Gradually

For high-impact changes, use phased rollout:

1. **Pilot**: Apply to 1-2 low-risk resources
2. **Monitor**: 24-48 hours observation
3. **Expand**: Roll out to 25% of resources
4. **Monitor**: Another 24-48 hours
5. **Complete**: Apply to all resources

### 3. Communication Plan

Notify stakeholders before making changes:

**Email Template**:
```
Subject: Scheduled Security Enhancement - [Control Name]

Team,

We will be implementing the following security enhancement:

What: [Control description]
When: [Date/Time]
Duration: [Estimated time]
Impact: [Expected impact on services/users]
Reason: [Security benefit]

What you need to do:
[Any required actions from teams/users]

Questions? Reply to this email or contact security@company.com

Remediation can be postponed if you have concerns.
```

### 4. Document Everything

Create runbook entry for each remediation:

```markdown
## [Control ID]: [Control Name]

Date Implemented: YYYY-MM-DD
Implemented By: [Name/Team]
Affected Resources: [List]
Changes Made: [Specific changes]
Rollback Tested: Yes/No
Issues Encountered: [Any problems]
Resolution: [How issues were resolved]
```

### 5. Monitor After Changes

Set up monitoring for successful remediation:

**Azure**:
```powershell
# Create alert for security policy compliance changes
$actionGroup = Get-AzActionGroup -ResourceGroupName "monitoring-rg" -Name "security-alerts"

New-AzMetricAlertRuleV2 -Name "SecurityComplianceChange" `
  -ResourceGroupName "monitoring-rg" `
  -WindowSize 00:05:00 `
  -Frequency 00:05:00 `
  -TargetResourceId "/subscriptions/SUBSCRIPTION_ID" `
  -Condition @(...)`
  -ActionGroup $actionGroup
```

**AWS**:
```bash
# Create CloudWatch alarm for Config compliance
aws cloudwatch put-metric-alarm \
  --alarm-name "ConfigComplianceChange" \
  --alarm-description "Alert on compliance changes" \
  --metric-name ComplianceScore \
  --namespace AWS/Config \
  --statistic Average \
  --period 300 \
  --evaluation-periods 1 \
  --threshold 95 \
  --comparison-operator LessThanThreshold \
  --alarm-actions arn:aws:sns:us-east-1:ACCOUNT_ID:security-alerts
```

---

## Troubleshooting Common Issues

### Azure: "Insufficient Permissions"

**Error**: `The client does not have authorization to perform action`

**Solution**:
```powershell
# Check your current role assignments
Get-AzRoleAssignment -SignInName your-email@company.com

# Request necessary role from administrator
# Required roles vary by control:
# - IAM controls: Global Administrator, Security Administrator
# - Logging: Monitoring Contributor, Log Analytics Contributor
# - Storage: Storage Account Contributor
# - Network: Network Contributor
```

### AWS: "Access Denied"

**Error**: `User is not authorized to perform: [action]`

**Solution**:
```bash
# Check your current permissions
aws iam get-user
aws iam list-attached-user-policies --user-name YOUR_USERNAME
aws iam list-user-policies --user-name YOUR_USERNAME

# Request policy attachment from administrator
# Common required policies:
# - IAM controls: IAMFullAccess
# - Logging: CloudTrailFullAccess, CloudWatchLogsFullAccess
# - Storage: AmazonS3FullAccess
```

### Azure: "Resource is Locked"

**Error**: `The resource is locked and cannot be modified`

**Solution**:
```powershell
# Identify locks
Get-AzResourceLock -ResourceGroupName "MyRG"

# Temporarily remove lock (with approval)
Remove-AzResourceLock -LockId "/subscriptions/.../locks/lock-name" -Force

# Make changes

# Re-apply lock
New-AzResourceLock -LockName "DoNotDelete" -LockLevel CanNotDelete -ResourceGroupName "MyRG"
```

### AWS: "Trail Already Exists"

**Error**: `Trail name already exists`

**Solution**:
```bash
# Update existing trail instead of creating new
aws cloudtrail update-trail --name existing-trail \
  --s3-bucket-name $BUCKET_NAME \
  --is-multi-region-trail \
  --enable-log-file-validation

# Or delete and recreate (requires justification)
aws cloudtrail delete-trail --name existing-trail
```

---

## Emergency Rollback Procedures

If remediation causes critical business impact:

### 1. Immediate Rollback

Execute rollback commands from the specific remediation section above.

### 2. Incident Communication

```
Subject: URGENT - Security Change Rollback

A security change has been temporarily rolled back due to business impact:

Control: [ID and Name]
Rollback Time: [Timestamp]
Reason: [Business impact description]
Current State: [Reverted to previous configuration]

Next Steps:
1. Root cause analysis: [Date]
2. Updated remediation plan: [Date]
3. Re-implementation: [Date]

Security risk during rollback: [Risk description]
Compensating controls: [Temporary mitigations]
```

### 3. Post-Incident Review

- Document what went wrong
- Update remediation procedure
- Identify missed dependencies
- Improve testing process
- Schedule re-implementation

---

**Next**: [06-ci-cd-integration.md](06-ci-cd-integration.md) for pipeline integration.
