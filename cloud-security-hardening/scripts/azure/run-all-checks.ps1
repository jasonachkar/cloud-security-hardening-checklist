#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Run All Azure Security Checks

.DESCRIPTION
    Executes all Azure security hardening checks and generates comprehensive report

.NOTES
    File Name: run-all-checks.ps1
    Author: Cloud Security Hardening Framework
    Version: 1.0.0

.EXAMPLE
    ./run-all-checks.ps1
    ./run-all-checks.ps1 | Tee-Object -FilePath report.txt
#>

[CmdletBinding()]
param(
    [switch]$ExitOnFailure = $true
)

$ErrorActionPreference = "Continue"
$ScriptDir = $PSScriptRoot
$StartTime = Get-Date

# Banner
Write-Host @"

╔══════════════════════════════════════════════════════════════════════════╗
║                                                                          ║
║            Azure Security Hardening Framework                            ║
║            CIS Microsoft Azure Foundations Benchmark v2.0.0              ║
║                                                                          ║
║            Production-Grade Security Assessment Tool                     ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan

Write-Host "Assessment Start Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White
Write-Host ""

# Verify Azure connection
$context = Get-AzContext -ErrorAction SilentlyContinue
if ($null -eq $context) {
    Write-Host "[ERROR] Not connected to Azure. Please run 'Connect-AzAccount' first." -ForegroundColor Red
    exit 1
}

Write-Host "[INFO] Azure Subscription: $($context.Subscription.Name)" -ForegroundColor Cyan
Write-Host "[INFO] Subscription ID: $($context.Subscription.Id)" -ForegroundColor Cyan
Write-Host "[INFO] Tenant ID: $($context.Tenant.Id)" -ForegroundColor Cyan
Write-Host ""

# Check scripts
$checks = @(
    @{ Name = "Identity & Access Management"; Script = "check-iam.ps1" },
    @{ Name = "Logging & Monitoring"; Script = "check-logging.ps1" },
    @{ Name = "Network Security"; Script = "check-network.ps1" },
    @{ Name = "Storage Security"; Script = "check-storage.ps1" },
    @{ Name = "Compute Security"; Script = "check-compute.ps1" }
)

$results = @()
$totalFailures = 0

foreach ($check in $checks) {
    $scriptPath = Join-Path $ScriptDir $check.Script

    if (-not (Test-Path $scriptPath)) {
        Write-Host "[WARN] Script not found: $scriptPath" -ForegroundColor Yellow
        continue
    }

    Write-Host "`n╔══════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Magenta
    Write-Host "║  Running: $($check.Name)" -ForegroundColor Magenta
    Write-Host "╚══════════════════════════════════════════════════════════════════════════╝`n" -ForegroundColor Magenta

    try {
        # Execute check
        $output = & $scriptPath 2>&1
        $exitCode = $LASTEXITCODE

        # Display output
        Write-Host $output

        # Track results
        $result = @{
            Category = $check.Name
            ExitCode = $exitCode
            Status = if ($exitCode -eq 0) { "PASS" } else { "FAIL" }
        }
        $results += $result

        if ($exitCode -ne 0) {
            $totalFailures++
        }
    }
    catch {
        Write-Host "[ERROR] Failed to execute $($check.Script): $_" -ForegroundColor Red
        $totalFailures++
    }
}

# Summary Report
$EndTime = Get-Date
$Duration = $EndTime - $StartTime

Write-Host "`n`n╔══════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                    ASSESSMENT SUMMARY REPORT                             ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan

Write-Host "Subscription: $($context.Subscription.Name)" -ForegroundColor White
Write-Host "Assessment Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White
Write-Host "Duration: $([math]::Round($Duration.TotalMinutes, 2)) minutes`n" -ForegroundColor White

Write-Host "Results by Category:" -ForegroundColor White
Write-Host "═══════════════════════════════════════════════════════════════════════════" -ForegroundColor Gray

foreach ($result in $results) {
    $statusColor = if ($result.Status -eq "PASS") { "Green" } else { "Red" }
    $statusSymbol = if ($result.Status -eq "PASS") { "✓" } else { "✗" }

    Write-Host ("{0,-40} [{1}] {2}" -f $result.Category, $statusSymbol, $result.Status) -ForegroundColor $statusColor
}

Write-Host "`n═══════════════════════════════════════════════════════════════════════════" -ForegroundColor Gray

$passCount = ($results | Where-Object { $_.Status -eq "PASS" }).Count
$failCount = ($results | Where-Object { $_.Status -eq "FAIL" }).Count
$totalChecks = $results.Count

if ($totalChecks -gt 0) {
    $complianceRate = [math]::Round(($passCount / $totalChecks) * 100, 2)
    $complianceColor = if ($complianceRate -ge 90) { "Green" } elseif ($complianceRate -ge 70) { "Yellow" } else { "Red" }

    Write-Host "`nOverall Compliance Rate: $complianceRate%" -ForegroundColor $complianceColor
    Write-Host "  Categories Passed: $passCount / $totalChecks" -ForegroundColor Green
    Write-Host "  Categories Failed: $failCount / $totalChecks" -ForegroundColor Red
}

Write-Host "`n═══════════════════════════════════════════════════════════════════════════" -ForegroundColor Gray

if ($totalFailures -gt 0) {
    Write-Host "`n⚠  ACTION REQUIRED: $totalFailures security check categor$(if($totalFailures -eq 1){'y'}else{'ies'}) failed" -ForegroundColor Red
    Write-Host "   Review failures above and consult remediation guide:" -ForegroundColor Yellow
    Write-Host "   docs/05-remediation-guide.md`n" -ForegroundColor Yellow

    if ($ExitOnFailure) {
        exit 1
    }
} else {
    Write-Host "`n✓  All security checks passed!" -ForegroundColor Green
    Write-Host "   Continue monitoring and schedule regular assessments.`n" -ForegroundColor Green
}

Write-Host "╔══════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  Assessment Complete                                                      ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan

exit 0
