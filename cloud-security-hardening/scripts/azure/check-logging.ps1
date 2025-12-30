#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Azure Logging & Monitoring Security Checks

.DESCRIPTION
    Performs read-only security checks on Azure logging and monitoring including:
    - Activity Log retention and export
    - Microsoft Defender for Cloud configuration
    - Diagnostic logging for resources
    - NSG Flow Logs
    - Log Analytics workspace configuration

.NOTES
    File Name: check-logging.ps1
    Author: Cloud Security Hardening Framework
    Requires: Az PowerShell Module
    Version: 1.0.0
#>

#Requires -Modules Az.Accounts, Az.Monitor, Az.Security, Az.Network

[CmdletBinding()]
param()

$ErrorActionPreference = "Continue"
$Script:FailureCount = 0
$Script:PassCount = 0
$Script:WarnCount = 0

function Write-Pass { param([string]$Message) Write-Host "[PASS] $Message" -ForegroundColor Green; $Script:PassCount++ }
function Write-Fail { param([string]$Message) Write-Host "[FAIL] $Message" -ForegroundColor Red; $Script:FailureCount++ }
function Write-Warn { param([string]$Message) Write-Host "[WARN] $Message" -ForegroundColor Yellow; $Script:WarnCount++ }
function Write-Info { param([string]$Message) Write-Host "[INFO] $Message" -ForegroundColor Cyan }
function Write-SectionHeader { param([string]$Title) Write-Host "`n========== $Title ==========" -ForegroundColor Magenta }

# AZ-LOG-01: Check Activity Log retention
function Test-ActivityLogRetention {
    Write-SectionHeader "AZ-LOG-01: Activity Log Retention and Export"

    try {
        $subscriptions = Get-AzSubscription

        foreach ($sub in $subscriptions) {
            Set-AzContext -SubscriptionId $sub.Id | Out-Null
            Write-Info "Checking subscription: $($sub.Name)"

            $diagnosticSettings = Get-AzDiagnosticSetting -ResourceId "/subscriptions/$($sub.Id)" -ErrorAction SilentlyContinue

            if ($null -eq $diagnosticSettings -or $diagnosticSettings.Count -eq 0) {
                Write-Fail "No diagnostic settings configured for Activity Log - subscription: $($sub.Name)"
                Write-Info "  CIS Control: 5.1.1"
                continue
            }

            $hasValidSettings = $false
            foreach ($setting in $diagnosticSettings) {
                if ($setting.WorkspaceId -or $setting.StorageAccountId) {
                    Write-Pass "Activity Log exported to Log Analytics or Storage - subscription: $($sub.Name)"
                    $hasValidSettings = $true

                    # Check retention if using storage
                    if ($setting.StorageAccountId) {
                        $retention = $setting.Log | Where-Object { $_.RetentionPolicy.Days -ge 365 }
                        if ($retention) {
                            Write-Pass "Activity Log retention >= 365 days - subscription: $($sub.Name)"
                        }
                        else {
                            Write-Warn "Activity Log retention < 365 days - subscription: $($sub.Name)"
                            Write-Info "  CIS Control: 5.1.2 - Recommend 365+ days retention"
                        }
                    }
                    break
                }
            }

            if (-not $hasValidSettings) {
                Write-Fail "Activity Log not exported to Log Analytics or Storage - subscription: $($sub.Name)"
            }
        }
    }
    catch {
        Write-Fail "Error checking Activity Log configuration: $_"
    }
}

# AZ-LOG-02: Check Microsoft Defender for Cloud
function Test-DefenderForCloud {
    Write-SectionHeader "AZ-LOG-02 & AZ-LOG-03: Microsoft Defender for Cloud"

    try {
        $subscriptions = Get-AzSubscription

        foreach ($sub in $subscriptions) {
            Set-AzContext -SubscriptionId $sub.Id | Out-Null
            Write-Info "Checking Defender for Cloud - subscription: $($sub.Name)"

            # Check Defender pricing tiers
            $pricings = Get-AzSecurityPricing -ErrorAction SilentlyContinue

            if ($null -eq $pricings) {
                Write-Warn "Unable to retrieve Defender for Cloud pricing information"
                continue
            }

            $requiredPlans = @(
                "VirtualMachines",
                "AppServices",
                "SqlServers",
                "StorageAccounts",
                "KubernetesService",
                "ContainerRegistry",
                "KeyVaults"
            )

            foreach ($plan in $requiredPlans) {
                $pricing = $pricings | Where-Object { $_.Name -eq $plan }
                if ($pricing -and $pricing.PricingTier -eq "Standard") {
                    Write-Pass "Defender for $plan enabled"
                }
                else {
                    Write-Fail "Defender for $plan not enabled or on Free tier"
                    Write-Info "  CIS Control: 2.1.x"
                }
            }

            # Check auto-provisioning
            $autoProvision = Get-AzSecurityAutoProvisioningSetting -ErrorAction SilentlyContinue
            if ($autoProvision -and $autoProvision.AutoProvision -eq "On") {
                Write-Pass "Auto-provisioning of monitoring agent enabled"
            }
            else {
                Write-Fail "Auto-provisioning of monitoring agent not enabled"
                Write-Info "  CIS Control: 2.1.15"
            }
        }
    }
    catch {
        Write-Fail "Error checking Defender for Cloud: $_"
    }
}

# AZ-LOG-04: Check diagnostic logging for resources
function Test-ResourceDiagnosticLogs {
    Write-SectionHeader "AZ-LOG-04: Diagnostic Logs for Resources"

    try {
        $subscriptions = Get-AzSubscription

        foreach ($sub in $subscriptions) {
            Set-AzContext -SubscriptionId $sub.Id | Out-Null
            Write-Info "Checking diagnostic logs - subscription: $($sub.Name)"

            # Check storage accounts
            $storageAccounts = Get-AzStorageAccount -ErrorAction SilentlyContinue
            foreach ($sa in $storageAccounts) {
                $diagnostics = Get-AzDiagnosticSetting -ResourceId $sa.Id -ErrorAction SilentlyContinue
                if ($diagnostics -and $diagnostics.Count -gt 0) {
                    Write-Pass "Diagnostic logs enabled for storage: $($sa.StorageAccountName)"
                }
                else {
                    Write-Warn "Diagnostic logs not enabled for storage: $($sa.StorageAccountName)"
                }
            }

            # Check Key Vaults
            $keyVaults = Get-AzKeyVault -ErrorAction SilentlyContinue
            foreach ($kv in $keyVaults) {
                $kvResource = Get-AzResource -ResourceId $kv.ResourceId
                $diagnostics = Get-AzDiagnosticSetting -ResourceId $kvResource.ResourceId -ErrorAction SilentlyContinue
                if ($diagnostics -and $diagnostics.Count -gt 0) {
                    Write-Pass "Diagnostic logs enabled for Key Vault: $($kv.VaultName)"
                }
                else {
                    Write-Fail "Diagnostic logs not enabled for Key Vault: $($kv.VaultName)"
                    Write-Info "  CIS Control: 5.1.4"
                }
            }
        }
    }
    catch {
        Write-Fail "Error checking resource diagnostic logs: $_"
    }
}

# AZ-LOG-05: Check NSG Flow Logs
function Test-NSGFlowLogs {
    Write-SectionHeader "AZ-LOG-05: Network Security Group Flow Logs"

    try {
        $subscriptions = Get-AzSubscription

        foreach ($sub in $subscriptions) {
            Set-AzContext -SubscriptionId $sub.Id | Out-Null
            Write-Info "Checking NSG Flow Logs - subscription: $($sub.Name)"

            $nsgs = Get-AzNetworkSecurityGroup -ErrorAction SilentlyContinue

            foreach ($nsg in $nsgs) {
                # Check if flow logs are enabled
                # Note: Flow logs are regional resources under Network Watcher
                $location = $nsg.Location

                try {
                    $networkWatcher = Get-AzNetworkWatcher -Location $location -ErrorAction SilentlyContinue
                    if ($networkWatcher) {
                        $flowLogs = Get-AzNetworkWatcherFlowLog -NetworkWatcher $networkWatcher -TargetResourceId $nsg.Id -ErrorAction SilentlyContinue

                        if ($flowLogs -and $flowLogs.Enabled) {
                            if ($flowLogs.RetentionPolicy.Days -ge 90) {
                                Write-Pass "NSG Flow Logs enabled with retention >= 90 days: $($nsg.Name)"
                            }
                            else {
                                Write-Warn "NSG Flow Logs enabled but retention < 90 days: $($nsg.Name)"
                                Write-Info "  Current retention: $($flowLogs.RetentionPolicy.Days) days"
                                Write-Info "  CIS Control: 6.6"
                            }
                        }
                        else {
                            Write-Fail "NSG Flow Logs not enabled: $($nsg.Name)"
                            Write-Info "  CIS Control: 6.6"
                        }
                    }
                }
                catch {
                    Write-Warn "Unable to check flow logs for NSG: $($nsg.Name) - Network Watcher may not be deployed in region: $location"
                }
            }
        }
    }
    catch {
        Write-Fail "Error checking NSG Flow Logs: $_"
    }
}

# Main execution
function Main {
    Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║   Azure Logging & Monitoring Security Checks                 ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan

    $context = Get-AzContext
    if ($null -eq $context) {
        Write-Host "[ERROR] Not connected to Azure. Run 'Connect-AzAccount' first." -ForegroundColor Red
        exit 1
    }
    Write-Info "Connected to Azure Subscription: $($context.Subscription.Name)`n"

    Test-ActivityLogRetention
    Test-DefenderForCloud
    Test-ResourceDiagnosticLogs
    Test-NSGFlowLogs

    # Summary
    Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║   Logging & Monitoring Check Summary                          ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan

    Write-Host "Results:" -ForegroundColor White
    Write-Host "  PASS: $Script:PassCount" -ForegroundColor Green
    Write-Host "  FAIL: $Script:FailureCount" -ForegroundColor Red
    Write-Host "  WARN: $Script:WarnCount`n" -ForegroundColor Yellow

    if ($Script:FailureCount -gt 0) { exit 1 }
    exit 0
}

Main
