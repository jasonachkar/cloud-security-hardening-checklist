#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Azure Network Security Checks
.DESCRIPTION
    Checks NSG rules, RDP/SSH exposure, and network configuration
.NOTES
    Version: 1.0.0
#>

#Requires -Modules Az.Network

[CmdletBinding()]
param()

$Script:FailureCount = 0; $Script:PassCount = 0; $Script:WarnCount = 0
function Write-Pass { param([string]$M) Write-Host "[PASS] $M" -ForegroundColor Green; $Script:PassCount++ }
function Write-Fail { param([string]$M) Write-Host "[FAIL] $M" -ForegroundColor Red; $Script:FailureCount++ }
function Write-Warn { param([string]$M) Write-Host "[WARN] $M" -ForegroundColor Yellow; $Script:WarnCount++ }
function Write-Info { param([string]$M) Write-Host "[INFO] $M" -ForegroundColor Cyan }

Write-Host "`n=== Azure Network Security Checks ===`n" -ForegroundColor Cyan

$subs = Get-AzSubscription
foreach ($sub in $subs) {
    Set-AzContext -SubscriptionId $sub.Id | Out-Null
    Write-Info "Checking subscription: $($sub.Name)"

    # Check NSGs for dangerous rules
    $nsgs = Get-AzNetworkSecurityGroup
    foreach ($nsg in $nsgs) {
        # Check for RDP from internet
        $rdpRules = $nsg.SecurityRules | Where-Object {
            $_.Direction -eq "Inbound" -and
            $_.Access -eq "Allow" -and
            $_.DestinationPortRange -contains "3389" -and
            ($_.SourceAddressPrefix -eq "*" -or $_.SourceAddressPrefix -eq "Internet" -or $_.SourceAddressPrefix -eq "0.0.0.0/0")
        }

        if ($rdpRules) {
            Write-Fail "RDP (3389) exposed to internet in NSG: $($nsg.Name) - CIS 6.1"
        } else {
            Write-Pass "RDP not exposed to internet in NSG: $($nsg.Name)"
        }

        # Check for SSH from internet
        $sshRules = $nsg.SecurityRules | Where-Object {
            $_.Direction -eq "Inbound" -and
            $_.Access -eq "Allow" -and
            ($_.DestinationPortRange -contains "22" -or $_.DestinationPortRange -eq "*") -and
            ($_.SourceAddressPrefix -eq "*" -or $_.SourceAddressPrefix -eq "Internet" -or $_.SourceAddressPrefix -eq "0.0.0.0/0")
        }

        if ($sshRules) {
            Write-Fail "SSH (22) exposed to internet in NSG: $($nsg.Name) - CIS 6.2"
        } else {
            Write-Pass "SSH not exposed to internet in NSG: $($nsg.Name)"
        }

        # Check for any allow-all rules
        $allowAllRules = $nsg.SecurityRules | Where-Object {
            $_.Direction -eq "Inbound" -and
            $_.Access -eq "Allow" -and
            $_.DestinationPortRange -eq "*" -and
            ($_.SourceAddressPrefix -eq "*" -or $_.SourceAddressPrefix -eq "0.0.0.0/0")
        }

        if ($allowAllRules) {
            Write-Fail "NSG allows all inbound traffic: $($nsg.Name) - CIS 6.3"
        } else {
            Write-Pass "NSG does not allow all inbound traffic: $($nsg.Name)"
        }
    }

    # Check Network Watcher
    $locations = (Get-AzLocation | Where-Object {$_.Providers -contains "Microsoft.Network"}).Location
    foreach ($loc in $locations) {
        $nw = Get-AzNetworkWatcher -Location $loc -ErrorAction SilentlyContinue
        if ($nw) {
            Write-Pass "Network Watcher enabled in region: $loc"
        } else {
            Write-Warn "Network Watcher not enabled in region: $loc - CIS 6.5"
        }
    }
}

Write-Host "`n=== Summary ===" -ForegroundColor Cyan
Write-Host "PASS: $Script:PassCount | FAIL: $Script:FailureCount | WARN: $Script:WarnCount`n"
if ($Script:FailureCount -gt 0) { exit 1 }
exit 0
