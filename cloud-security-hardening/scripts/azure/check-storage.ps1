#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Azure Storage Security Checks
.DESCRIPTION
    Checks storage account security: public access, encryption, secure transfer, Key Vault
.NOTES
    Version: 1.0.0
#>

#Requires -Modules Az.Storage, Az.KeyVault

[CmdletBinding()]
param()

$Script:FailureCount = 0; $Script:PassCount = 0; $Script:WarnCount = 0
function Write-Pass { param([string]$M) Write-Host "[PASS] $M" -ForegroundColor Green; $Script:PassCount++ }
function Write-Fail { param([string]$M) Write-Host "[FAIL] $M" -ForegroundColor Red; $Script:FailureCount++ }
function Write-Warn { param([string]$M) Write-Host "[WARN] $M" -ForegroundColor Yellow; $Script:WarnCount++ }
function Write-Info { param([string]$M) Write-Host "[INFO] $M" -ForegroundColor Cyan }

Write-Host "`n=== Azure Storage Security Checks ===`n" -ForegroundColor Cyan

$subs = Get-AzSubscription
foreach ($sub in $subs) {
    Set-AzContext -SubscriptionId $sub.Id | Out-Null
    Write-Info "Checking subscription: $($sub.Name)"

    # Check storage accounts
    $storageAccounts = Get-AzStorageAccount
    foreach ($sa in $storageAccounts) {
        # AZ-STORAGE-01: Secure transfer
        if ($sa.EnableHttpsTrafficOnly) {
            Write-Pass "Secure transfer (HTTPS) required: $($sa.StorageAccountName) - CIS 3.1"
        } else {
            Write-Fail "Secure transfer not required: $($sa.StorageAccountName) - CIS 3.1"
        }

        # AZ-STORAGE-02: Public blob access
        if ($sa.AllowBlobPublicAccess -eq $false) {
            Write-Pass "Public blob access disabled: $($sa.StorageAccountName) - CIS 3.2"
        } else {
            Write-Fail "Public blob access enabled: $($sa.StorageAccountName) - CIS 3.2"
        }

        # AZ-STORAGE-03: Encryption
        if ($sa.Encryption.Services.Blob.Enabled -and $sa.Encryption.Services.File.Enabled) {
            Write-Pass "Encryption enabled for Blob and File services: $($sa.StorageAccountName) - CIS 3.3, 3.4"
        } else {
            Write-Fail "Encryption not fully enabled: $($sa.StorageAccountName)"
        }

        # AZ-STORAGE-10: TLS version
        if ($sa.MinimumTlsVersion -eq "TLS1_2") {
            Write-Pass "Minimum TLS version 1.2: $($sa.StorageAccountName)"
        } else {
            Write-Fail "Minimum TLS version not 1.2: $($sa.StorageAccountName) (Current: $($sa.MinimumTlsVersion))"
        }

        # AZ-STORAGE-05: Network access
        if ($sa.NetworkRuleSet.DefaultAction -eq "Deny") {
            Write-Pass "Default network access denied: $($sa.StorageAccountName) - CIS 3.7"
        } else {
            Write-Warn "Default network access not denied: $($sa.StorageAccountName) - CIS 3.7"
        }
    }

    # Check Key Vaults
    $keyVaults = Get-AzKeyVault
    foreach ($kv in $keyVaults) {
        $kvDetails = Get-AzKeyVault -VaultName $kv.VaultName

        # AZ-KV-04: Soft delete and purge protection
        if ($kvDetails.EnableSoftDelete) {
            Write-Pass "Soft delete enabled for Key Vault: $($kv.VaultName) - CIS 8.4"
        } else {
            Write-Fail "Soft delete not enabled for Key Vault: $($kv.VaultName) - CIS 8.4"
        }

        if ($kvDetails.EnablePurgeProtection) {
            Write-Pass "Purge protection enabled for Key Vault: $($kv.VaultName) - CIS 8.4"
        } else {
            Write-Fail "Purge protection not enabled for Key Vault: $($kv.VaultName) - CIS 8.4"
        }

        # AZ-KV-01 & AZ-KV-02: Check for keys/secrets without expiration
        $keys = Get-AzKeyVaultKey -VaultName $kv.VaultName
        $keysWithoutExpiry = $keys | Where-Object { $null -eq $_.Expires }
        if ($keysWithoutExpiry.Count -gt 0) {
            Write-Warn "Found $($keysWithoutExpiry.Count) keys without expiration in: $($kv.VaultName) - CIS 8.1"
        } else {
            Write-Pass "All keys have expiration dates in Key Vault: $($kv.VaultName)"
        }

        $secrets = Get-AzKeyVaultSecret -VaultName $kv.VaultName
        $secretsWithoutExpiry = $secrets | Where-Object { $null -eq $_.Expires }
        if ($secretsWithoutExpiry.Count -gt 0) {
            Write-Warn "Found $($secretsWithoutExpiry.Count) secrets without expiration in: $($kv.VaultName) - CIS 8.2"
        } else {
            Write-Pass "All secrets have expiration dates in Key Vault: $($kv.VaultName)"
        }
    }
}

Write-Host "`n=== Summary ===" -ForegroundColor Cyan
Write-Host "PASS: $Script:PassCount | FAIL: $Script:FailureCount | WARN: $Script:WarnCount`n"
if ($Script:FailureCount -gt 0) { exit 1 }
exit 0
