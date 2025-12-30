#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Azure Compute Security Checks
.DESCRIPTION
    Checks VM disk encryption, managed disks, extensions
.NOTES
    Version: 1.0.0
#>

#Requires -Modules Az.Compute

[CmdletBinding()]
param()

$Script:FailureCount = 0; $Script:PassCount = 0; $Script:WarnCount = 0
function Write-Pass { param([string]$M) Write-Host "[PASS] $M" -ForegroundColor Green; $Script:PassCount++ }
function Write-Fail { param([string]$M) Write-Host "[FAIL] $M" -ForegroundColor Red; $Script:FailureCount++ }
function Write-Warn { param([string]$M) Write-Host "[WARN] $M" -ForegroundColor Yellow; $Script:WarnCount++ }
function Write-Info { param([string]$M) Write-Host "[INFO] $M" -ForegroundColor Cyan }

Write-Host "`n=== Azure Compute Security Checks ===`n" -ForegroundColor Cyan

$subs = Get-AzSubscription
foreach ($sub in $subs) {
    Set-AzContext -SubscriptionId $sub.Id | Out-Null
    Write-Info "Checking subscription: $($sub.Name)"

    # Check VMs
    $vms = Get-AzVM
    foreach ($vm in $vms) {
        # AZ-COMPUTE-01: Managed disks
        if ($vm.StorageProfile.OsDisk.ManagedDisk) {
            Write-Pass "VM uses managed disks: $($vm.Name) - CIS 7.1"
        } else {
            Write-Fail "VM uses unmanaged disks: $($vm.Name) - CIS 7.1"
        }

        # AZ-COMPUTE-02: OS disk encryption
        $vmStatus = Get-AzVM -ResourceGroupName $vm.ResourceGroupName -Name $vm.Name -Status
        $diskEncryption = $vmStatus.Extensions | Where-Object { $_.Type -like "*DiskEncryption*" }

        if ($diskEncryption) {
            Write-Pass "Disk encryption enabled for VM: $($vm.Name) - CIS 7.2"
        } else {
            Write-Warn "Disk encryption not detected for VM: $($vm.Name) - CIS 7.2"
            Write-Info "  Verify Azure Disk Encryption is enabled"
        }

        # AZ-COMPUTE-04: Check extensions
        $extensions = $vm.Extensions
        if ($extensions.Count -gt 0) {
            Write-Info "VM $($vm.Name) has $($extensions.Count) extensions installed"
            foreach ($ext in $extensions) {
                Write-Info "  - $($ext.Publisher)/$($ext.VirtualMachineExtensionType)"
            }
        }

        # AZ-COMPUTE-05: Endpoint protection check
        $epExtensions = $extensions | Where-Object {
            $_.Publisher -like "*TrendMicro*" -or
            $_.Publisher -like "*Symantec*" -or
            $_.Publisher -like "*McAfee*" -or
            $_.Publisher -like "*Microsoft.Azure.Security*"
        }

        if ($epExtensions) {
            Write-Pass "Endpoint protection detected on VM: $($vm.Name) - CIS 7.5"
        } else {
            Write-Warn "No endpoint protection extension detected on VM: $($vm.Name) - CIS 7.5"
        }
    }

    # AZ-COMPUTE-03: Check for unattached encrypted disks
    $disks = Get-AzDisk
    $unattachedDisks = $disks | Where-Object { $null -eq $_.ManagedBy }

    foreach ($disk in $unattachedDisks) {
        if ($disk.Encryption.Type -eq "EncryptionAtRestWithPlatformKey" -or
            $disk.Encryption.Type -eq "EncryptionAtRestWithCustomerKey") {
            Write-Pass "Unattached disk is encrypted: $($disk.Name) - CIS 7.3"
        } else {
            Write-Fail "Unattached disk not encrypted: $($disk.Name) - CIS 7.3"
        }
    }
}

Write-Host "`n=== Summary ===" -ForegroundColor Cyan
Write-Host "PASS: $Script:PassCount | FAIL: $Script:FailureCount | WARN: $Script:WarnCount`n"
if ($Script:FailureCount -gt 0) { exit 1 }
exit 0
