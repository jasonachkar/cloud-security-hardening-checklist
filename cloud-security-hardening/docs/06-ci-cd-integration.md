# CI/CD Pipeline Integration Guide

## Overview

This guide explains how to integrate cloud security hardening checks into CI/CD pipelines for continuous security validation. Security checks can prevent deployment of non-compliant infrastructure and detect configuration drift.

## Integration Objectives

1. **Shift Left**: Detect security issues before deployment
2. **Fail Fast**: Stop deployments that violate security policies
3. **Continuous Monitoring**: Schedule regular security scans
4. **Audit Trail**: Log security check results for compliance
5. **Alert**: Notify security team of failures

## Integration Patterns

### Pattern 1: Pre-Deployment Gate

Run security checks before deploying infrastructure changes. Fail the build if critical violations are found.

```
Code Commit → Build → Security Scan → Deploy (if pass)
                           ↓
                     Fail build (if FAIL)
```

### Pattern 2: Post-Deployment Validation

Deploy infrastructure, then verify security configuration. Rollback if checks fail.

```
Code Commit → Build → Deploy → Security Scan
                                   ↓
                          Rollback (if FAIL)
```

### Pattern 3: Scheduled Compliance Scan

Run security checks on a schedule (daily, weekly) to detect configuration drift.

```
Cron/Scheduler → Security Scan → Report → Alert (if failures)
```

### Pattern 4: Pull Request Validation

Run security checks on Infrastructure-as-Code in pull requests.

```
PR Created → IaC Analysis → Comment on PR → Approve/Request Changes
```

---

## GitHub Actions Integration

### Basic Azure Security Scan

```yaml
name: Azure Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    # Run daily at 2 AM UTC
    - cron: '0 2 * * *'

env:
  SUBSCRIPTION_ID: ${{ secrets.AZURE_SUBSCRIPTION_ID }}

jobs:
  azure-security-scan:
    runs-on: ubuntu-latest
    permissions:
      id-token: write  # For OIDC authentication
      contents: read
      issues: write    # To create issues for failures

    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Azure Login (OIDC)
        uses: azure/login@v1
        with:
          client-id: ${{ secrets.AZURE_CLIENT_ID }}
          tenant-id: ${{ secrets.AZURE_TENANT_ID }}
          subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}

      - name: Install PowerShell
        run: |
          sudo apt-get update
          sudo apt-get install -y powershell

      - name: Run IAM Security Checks
        id: iam-check
        continue-on-error: true
        run: |
          pwsh ./scripts/azure/check-iam.ps1 | tee iam-results.txt
          echo "iam_result=$?" >> $GITHUB_OUTPUT

      - name: Run Logging Security Checks
        id: logging-check
        continue-on-error: true
        run: |
          pwsh ./scripts/azure/check-logging.ps1 | tee logging-results.txt
          echo "logging_result=$?" >> $GITHUB_OUTPUT

      - name: Run Network Security Checks
        id: network-check
        continue-on-error: true
        run: |
          pwsh ./scripts/azure/check-network.ps1 | tee network-results.txt
          echo "network_result=$?" >> $GITHUB_OUTPUT

      - name: Run Storage Security Checks
        id: storage-check
        continue-on-error: true
        run: |
          pwsh ./scripts/azure/check-storage.ps1 | tee storage-results.txt
          echo "storage_result=$?" >> $GITHUB_OUTPUT

      - name: Run Compute Security Checks
        id: compute-check
        continue-on-error: true
        run: |
          pwsh ./scripts/azure/check-compute.ps1 | tee compute-results.txt
          echo "compute_result=$?" >> $GITHUB_OUTPUT

      - name: Consolidate Results
        run: |
          cat iam-results.txt logging-results.txt network-results.txt \
              storage-results.txt compute-results.txt > azure-security-report.txt

      - name: Upload Security Report
        uses: actions/upload-artifact@v4
        with:
          name: azure-security-report
          path: azure-security-report.txt
          retention-days: 90

      - name: Check for Failures
        run: |
          if grep -q '\[FAIL\]' azure-security-report.txt; then
            echo "::error::Security check failures detected"
            exit 1
          else
            echo "::notice::All security checks passed"
          fi

      - name: Create Issue for Failures
        if: failure()
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const report = fs.readFileSync('azure-security-report.txt', 'utf8');
            const failures = report.split('\n').filter(line => line.includes('[FAIL]'));

            const issueBody = `## Azure Security Scan Failures

            **Date**: ${new Date().toISOString()}
            **Workflow**: ${context.workflow}
            **Run**: ${context.runNumber}

            ### Failed Controls

            \`\`\`
            ${failures.join('\n')}
            \`\`\`

            ### Full Report

            See [workflow run](${context.payload.repository.html_url}/actions/runs/${context.runId}) for complete details.

            ### Action Required

            Review and remediate failed controls according to the [Remediation Guide](docs/05-remediation-guide.md).
            `;

            await github.rest.issues.create({
              owner: context.repo.owner,
              repo: context.repo.repo,
              title: `Azure Security Scan Failures - ${new Date().toISOString().split('T')[0]}`,
              body: issueBody,
              labels: ['security', 'automated']
            });
```

### Basic AWS Security Scan

```yaml
name: AWS Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 2 * * *'

env:
  AWS_REGION: us-east-1

jobs:
  aws-security-scan:
    runs-on: ubuntu-latest
    permissions:
      id-token: write  # For OIDC authentication
      contents: read
      issues: write

    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Configure AWS Credentials (OIDC)
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AWS_ROLE_ARN }}
          aws-region: ${{ env.AWS_REGION }}

      - name: Make scripts executable
        run: chmod +x scripts/aws/*.sh

      - name: Run IAM Security Checks
        continue-on-error: true
        run: |
          ./scripts/aws/check-iam.sh | tee iam-results.txt
          echo "iam_exit_code=$?" >> $GITHUB_ENV

      - name: Run Logging Security Checks
        continue-on-error: true
        run: |
          ./scripts/aws/check-logging.sh | tee logging-results.txt
          echo "logging_exit_code=$?" >> $GITHUB_ENV

      - name: Run Network Security Checks
        continue-on-error: true
        run: |
          ./scripts/aws/check-network.sh | tee network-results.txt
          echo "network_exit_code=$?" >> $GITHUB_ENV

      - name: Run Storage Security Checks
        continue-on-error: true
        run: |
          ./scripts/aws/check-storage.sh | tee storage-results.txt
          echo "storage_exit_code=$?" >> $GITHUB_ENV

      - name: Run Compute Security Checks
        continue-on-error: true
        run: |
          ./scripts/aws/check-compute.sh | tee compute-results.txt
          echo "compute_exit_code=$?" >> $GITHUB_ENV

      - name: Consolidate Results
        run: |
          cat iam-results.txt logging-results.txt network-results.txt \
              storage-results.txt compute-results.txt > aws-security-report.txt

      - name: Upload Security Report
        uses: actions/upload-artifact@v4
        with:
          name: aws-security-report
          path: aws-security-report.txt
          retention-days: 90

      - name: Parse Results and Generate Metrics
        run: |
          TOTAL=$(grep -E '\[(PASS|FAIL|WARN)\]' aws-security-report.txt | wc -l)
          PASS=$(grep '\[PASS\]' aws-security-report.txt | wc -l)
          FAIL=$(grep '\[FAIL\]' aws-security-report.txt | wc -l)
          WARN=$(grep '\[WARN\]' aws-security-report.txt | wc -l)

          echo "Total Checks: $TOTAL"
          echo "Passed: $PASS"
          echo "Failed: $FAIL"
          echo "Warnings: $WARN"

          COMPLIANCE_RATE=$(( PASS * 100 / TOTAL ))
          echo "Compliance Rate: $COMPLIANCE_RATE%"

          echo "compliance_rate=$COMPLIANCE_RATE" >> $GITHUB_ENV

      - name: Comment on PR
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const report = fs.readFileSync('aws-security-report.txt', 'utf8');
            const failures = report.split('\n').filter(line => line.includes('[FAIL]'));
            const warnings = report.split('\n').filter(line => line.includes('[WARN]'));

            let comment = `## AWS Security Scan Results\n\n`;
            comment += `**Compliance Rate**: ${process.env.compliance_rate}%\n\n`;

            if (failures.length > 0) {
              comment += `### ❌ Failures (${failures.length})\n\n\`\`\`\n${failures.slice(0, 10).join('\n')}\n\`\`\`\n\n`;
            }

            if (warnings.length > 0) {
              comment += `### ⚠️ Warnings (${warnings.length})\n\n\`\`\`\n${warnings.slice(0, 5).join('\n')}\n\`\`\`\n\n`;
            }

            if (failures.length === 0) {
              comment += `### ✅ All security checks passed!\n\n`;
            }

            await github.rest.issues.createComment({
              owner: context.repo.owner,
              repo: context.repo.repo,
              issue_number: context.issue.number,
              body: comment
            });

      - name: Fail if Critical Issues Found
        run: |
          if grep -q '\[FAIL\]' aws-security-report.txt; then
            echo "::error::Security check failures detected"
            exit 1
          fi
```

---

## Azure DevOps Pipeline Integration

### Azure Security Pipeline

```yaml
# azure-pipelines-security.yml

trigger:
  branches:
    include:
      - main
  paths:
    include:
      - 'infrastructure/*'

schedules:
  - cron: "0 2 * * *"
    displayName: Daily security scan
    branches:
      include:
        - main

pool:
  vmImage: 'ubuntu-latest'

variables:
  - group: azure-credentials  # Variable group with service principal

stages:
  - stage: SecurityScan
    displayName: 'Azure Security Scan'
    jobs:
      - job: RunSecurityChecks
        displayName: 'Run Security Checks'
        steps:
          - checkout: self

          - task: AzureCLI@2
            displayName: 'Azure Login'
            inputs:
              azureSubscription: 'Azure-Service-Connection'
              scriptType: 'bash'
              scriptLocation: 'inlineScript'
              inlineScript: |
                az account show

          - task: PowerShell@2
            displayName: 'Install Az PowerShell Module'
            inputs:
              targetType: 'inline'
              script: |
                Install-Module -Name Az -Force -AllowClobber -Scope CurrentUser

          - task: PowerShell@2
            displayName: 'Run IAM Checks'
            continueOnError: true
            inputs:
              targetType: 'filePath'
              filePath: '$(System.DefaultWorkingDirectory)/scripts/azure/check-iam.ps1'
              pwsh: true
            env:
              AZURE_SUBSCRIPTION_ID: $(AZURE_SUBSCRIPTION_ID)

          - task: PowerShell@2
            displayName: 'Run Logging Checks'
            continueOnError: true
            inputs:
              targetType: 'filePath'
              filePath: '$(System.DefaultWorkingDirectory)/scripts/azure/check-logging.ps1'
              pwsh: true

          - task: PowerShell@2
            displayName: 'Run Network Checks'
            continueOnError: true
            inputs:
              targetType: 'filePath'
              filePath: '$(System.DefaultWorkingDirectory)/scripts/azure/check-network.ps1'
              pwsh: true

          - task: PowerShell@2
            displayName: 'Run Storage Checks'
            continueOnError: true
            inputs:
              targetType: 'filePath'
              filePath: '$(System.DefaultWorkingDirectory)/scripts/azure/check-storage.ps1'
              pwsh: true

          - task: PowerShell@2
            displayName: 'Run Compute Checks'
            continueOnError: true
            inputs:
              targetType: 'filePath'
              filePath: '$(System.DefaultWorkingDirectory)/scripts/azure/check-compute.ps1'
              pwsh: true

          - task: PowerShell@2
            displayName: 'Consolidate Results'
            inputs:
              targetType: 'inline'
              script: |
                Get-Content *.txt | Out-File -FilePath azure-security-report.txt

                $failures = Select-String -Path azure-security-report.txt -Pattern "\[FAIL\]"
                if ($failures) {
                  Write-Host "##vso[task.logissue type=error]Security failures detected"
                  Write-Host "##vso[task.complete result=Failed;]"
                } else {
                  Write-Host "##vso[task.logissue type=success]All security checks passed"
                }

          - task: PublishBuildArtifacts@1
            displayName: 'Publish Security Report'
            inputs:
              PathtoPublish: 'azure-security-report.txt'
              ArtifactName: 'security-report'
              publishLocation: 'Container'

          - task: PublishTestResults@2
            displayName: 'Publish Security Results'
            condition: always()
            inputs:
              testResultsFormat: 'JUnit'
              testResultsFiles: '**/security-results.xml'
              mergeTestResults: true
              failTaskOnFailedTests: true
              testRunTitle: 'Azure Security Compliance'
```

### AWS Security Pipeline

```yaml
# azure-pipelines-aws-security.yml

trigger:
  branches:
    include:
      - main

pool:
  vmImage: 'ubuntu-latest'

variables:
  - group: aws-credentials

stages:
  - stage: AWSSecurityScan
    displayName: 'AWS Security Scan'
    jobs:
      - job: RunSecurityChecks
        displayName: 'Run Security Checks'
        steps:
          - checkout: self

          - task: AWSCLI@1
            displayName: 'Configure AWS Credentials'
            inputs:
              awsCredentials: 'AWS-Service-Connection'
              regionName: 'us-east-1'

          - bash: |
              chmod +x scripts/aws/*.sh
            displayName: 'Make scripts executable'

          - bash: |
              ./scripts/aws/run-all-checks.sh > aws-security-report.txt
            displayName: 'Run All Security Checks'
            continueOnError: true

          - bash: |
              if grep -q '\[FAIL\]' aws-security-report.txt; then
                echo "##vso[task.logissue type=error]Security failures detected"
                echo "##vso[task.complete result=Failed;]"
              fi
            displayName: 'Check for Failures'

          - task: PublishBuildArtifacts@1
            inputs:
              PathtoPublish: 'aws-security-report.txt'
              ArtifactName: 'aws-security-report'
```

---

## GitLab CI Integration

### `.gitlab-ci.yml` for AWS

```yaml
stages:
  - security-scan
  - report

variables:
  AWS_DEFAULT_REGION: us-east-1

aws-security-scan:
  stage: security-scan
  image: amazon/aws-cli:latest
  before_script:
    - yum install -y jq
    - chmod +x scripts/aws/*.sh
  script:
    - ./scripts/aws/run-all-checks.sh | tee aws-security-report.txt
  artifacts:
    reports:
      junit: aws-security-results.xml
    paths:
      - aws-security-report.txt
    expire_in: 90 days
  allow_failure: false
  rules:
    - if: '$CI_PIPELINE_SOURCE == "schedule"'
    - if: '$CI_COMMIT_BRANCH == "main"'

security-report:
  stage: report
  image: alpine:latest
  dependencies:
    - aws-security-scan
  script:
    - apk add --no-cache grep
    - |
      TOTAL=$(grep -E '\[(PASS|FAIL|WARN)\]' aws-security-report.txt | wc -l)
      PASS=$(grep '\[PASS\]' aws-security-report.txt | wc -l)
      FAIL=$(grep '\[FAIL\]' aws-security-report.txt | wc -l)

      echo "Security Scan Summary:"
      echo "Total Checks: $TOTAL"
      echo "Passed: $PASS"
      echo "Failed: $FAIL"

      if [ $FAIL -gt 0 ]; then
        echo "Security scan failed with $FAIL failures"
        exit 1
      fi
  when: always
```

---

## Jenkins Integration

### Jenkinsfile for Azure

```groovy
pipeline {
    agent any

    environment {
        AZURE_SUBSCRIPTION_ID = credentials('azure-subscription-id')
    }

    triggers {
        cron('H 2 * * *')  // Daily at 2 AM
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Azure Login') {
            steps {
                withCredentials([azureServicePrincipal('azure-service-principal')]) {
                    sh 'az login --service-principal -u $AZURE_CLIENT_ID -p $AZURE_CLIENT_SECRET --tenant $AZURE_TENANT_ID'
                    sh 'az account set --subscription $AZURE_SUBSCRIPTION_ID'
                }
            }
        }

        stage('Security Scans') {
            parallel {
                stage('IAM Check') {
                    steps {
                        sh 'pwsh ./scripts/azure/check-iam.ps1 | tee iam-results.txt'
                    }
                }
                stage('Logging Check') {
                    steps {
                        sh 'pwsh ./scripts/azure/check-logging.ps1 | tee logging-results.txt'
                    }
                }
                stage('Network Check') {
                    steps {
                        sh 'pwsh ./scripts/azure/check-network.ps1 | tee network-results.txt'
                    }
                }
                stage('Storage Check') {
                    steps {
                        sh 'pwsh ./scripts/azure/check-storage.ps1 | tee storage-results.txt'
                    }
                }
                stage('Compute Check') {
                    steps {
                        sh 'pwsh ./scripts/azure/check-compute.ps1 | tee compute-results.txt'
                    }
                }
            }
        }

        stage('Consolidate Results') {
            steps {
                sh 'cat *-results.txt > azure-security-report.txt'
                archiveArtifacts artifacts: 'azure-security-report.txt', fingerprint: true
            }
        }

        stage('Check for Failures') {
            steps {
                script {
                    def report = readFile('azure-security-report.txt')
                    if (report.contains('[FAIL]')) {
                        error('Security check failures detected')
                    } else {
                        echo 'All security checks passed'
                    }
                }
            }
        }
    }

    post {
        failure {
            emailext (
                subject: "Azure Security Scan Failed: ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                body: """
                    Azure security scan has detected failures.

                    Job: ${env.JOB_NAME}
                    Build: ${env.BUILD_NUMBER}
                    URL: ${env.BUILD_URL}

                    Please review the security report and remediate failures.
                """,
                to: 'security-team@company.com',
                attachmentsPattern: 'azure-security-report.txt'
            )
        }
        always {
            cleanWs()
        }
    }
}
```

---

## Terraform Cloud/Enterprise Integration

### Sentinel Policy

Create a Sentinel policy to enforce security checks before Terraform apply:

```hcl
# sentinel.hcl

policy "azure-security-hardening" {
  source = "./azure-security-hardening.sentinel"
  enforcement_level = "hard-mandatory"
}

policy "aws-security-hardening" {
  source = "./aws-security-hardening.sentinel"
  enforcement_level = "hard-mandatory"
}
```

### Run Task Integration

```json
{
  "data": {
    "type": "tasks",
    "attributes": {
      "name": "Azure Security Scan",
      "url": "https://your-webhook-endpoint.com/azure-security-scan",
      "category": "task",
      "enabled": true,
      "enforcement-level": "mandatory"
    }
  }
}
```

Webhook handler would execute security scripts and return results.

---

## Notifications and Alerting

### Slack Notification

```bash
#!/bin/bash
# send-slack-notification.sh

SLACK_WEBHOOK_URL="$1"
REPORT_FILE="$2"
STATUS="$3"

FAILURES=$(grep '\[FAIL\]' "$REPORT_FILE" | wc -l)
WARNINGS=$(grep '\[WARN\]' "$REPORT_FILE" | wc -l)

if [ "$STATUS" = "failed" ]; then
  COLOR="danger"
  MESSAGE="Security scan failed with $FAILURES failures and $WARNINGS warnings"
else
  COLOR="good"
  MESSAGE="Security scan passed with $WARNINGS warnings"
fi

curl -X POST "$SLACK_WEBHOOK_URL" \
  -H 'Content-Type: application/json' \
  -d "{
    \"attachments\": [{
      \"color\": \"$COLOR\",
      \"title\": \"Cloud Security Scan Results\",
      \"text\": \"$MESSAGE\",
      \"fields\": [
        {\"title\": \"Failures\", \"value\": \"$FAILURES\", \"short\": true},
        {\"title\": \"Warnings\", \"value\": \"$WARNINGS\", \"short\": true}
      ]
    }]
  }"
```

### Microsoft Teams Notification

```powershell
# Send-TeamsNotification.ps1

param(
    [string]$WebhookUrl,
    [string]$ReportFile,
    [string]$Status
)

$report = Get-Content $ReportFile -Raw
$failures = ($report | Select-String -Pattern "\[FAIL\]" -AllMatches).Matches.Count
$warnings = ($report | Select-String -Pattern "\[WARN\]" -AllMatches).Matches.Count

$color = if ($Status -eq "failed") { "FF0000" } else { "00FF00" }

$body = @{
    "@type" = "MessageCard"
    "@context" = "https://schema.org/extensions"
    "summary" = "Cloud Security Scan Results"
    "themeColor" = $color
    "title" = "Cloud Security Scan Results"
    "sections" = @(
        @{
            "activityTitle" = "Security Scan Completed"
            "facts" = @(
                @{ "name" = "Status"; "value" = $Status },
                @{ "name" = "Failures"; "value" = $failures },
                @{ "name" = "Warnings"; "value" = $warnings }
            )
        }
    )
} | ConvertTo-Json -Depth 10

Invoke-RestMethod -Uri $WebhookUrl -Method Post -Body $body -ContentType 'application/json'
```

---

## Best Practices

### 1. Separate Security Scanning from Deployment

```yaml
# Don't do this:
- Deploy infrastructure
- Run security scan
- Hope it passes

# Do this:
- Run security scan on existing environment
- If pass, deploy changes
- Run security scan again to verify
```

### 2. Use Different Thresholds for Different Environments

```yaml
# Dev: Allow warnings, fail on critical only
# Staging: Fail on high and critical
# Production: Fail on medium, high, and critical

- name: Check Severity Threshold
  run: |
    ENV="${{ github.ref }}"
    if [[ "$ENV" == "refs/heads/main" ]]; then
      THRESHOLD="medium"
    elif [[ "$ENV" == "refs/heads/staging" ]]; then
      THRESHOLD="high"
    else
      THRESHOLD="critical"
    fi
```

### 3. Cache Results to Avoid Rate Limiting

```yaml
- name: Cache Security Scan Results
  uses: actions/cache@v3
  with:
    path: ~/.security-scan-cache
    key: security-scan-${{ hashFiles('infrastructure/**') }}
```

### 4. Run Scans in Parallel

```yaml
jobs:
  azure-iam:
    runs-on: ubuntu-latest
    steps: [...]

  azure-network:
    runs-on: ubuntu-latest
    steps: [...]

  azure-storage:
    runs-on: ubuntu-latest
    steps: [...]
```

### 5. Track Compliance Over Time

```yaml
- name: Send Metrics to Monitoring System
  run: |
    COMPLIANCE_RATE=$(calculate_compliance)
    curl -X POST monitoring-system.com/metrics \
      -d "compliance_rate=$COMPLIANCE_RATE"
```

---

## Troubleshooting

### "Pipeline takes too long"

**Solution**: Run checks in parallel, cache results, or run less frequently for non-critical environments.

### "Authentication failures in CI/CD"

**Solution**: Use OIDC federation instead of long-lived credentials:

**GitHub Actions + Azure**:
```yaml
- uses: azure/login@v1
  with:
    client-id: ${{ secrets.AZURE_CLIENT_ID }}
    tenant-id: ${{ secrets.AZURE_TENANT_ID }}
    subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
```

**GitHub Actions + AWS**:
```yaml
- uses: aws-actions/configure-aws-credentials@v4
  with:
    role-to-assume: arn:aws:iam::ACCOUNT_ID:role/GitHubActionsRole
    aws-region: us-east-1
```

### "Too many false positives"

**Solution**: Tune thresholds, add exceptions for approved deviations, improve control logic.

---

## Metrics and Reporting

Track these KPIs for security automation effectiveness:

- **Compliance Rate**: % of controls passing
- **Mean Time to Remediation**: Time from finding to fix
- **Scan Frequency**: How often scans run
- **False Positive Rate**: % of failures that are not actual risks
- **Coverage**: % of resources scanned vs. total resources

---

**Next**: Review [07-limitations-and-assumptions.md](07-limitations-and-assumptions.md) for framework boundaries.
