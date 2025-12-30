#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Azure Identity & Access Management (IAM) Security Checks

.DESCRIPTION
    Performs read-only security checks on Azure IAM configuration including:
    - Multi-factor authentication enforcement
    - Privileged access management
    - Guest user restrictions
    - Application registration settings
    - Conditional Access policies

.NOTES
    File Name: check-iam.ps1
    Author: Cloud Security Hardening Framework
    Requires: Az PowerShell Module, authenticated Azure session
    Version: 1.0.0

.EXAMPLE
    ./check-iam.ps1

.LINK
    https://github.com/your-repo/cloud-security-hardening
#>

#Requires -Modules Az.Accounts, Az.Resources

[CmdletBinding()]
param()

# Script configuration
$ErrorActionPreference = "Continue"
$WarningPreference = "SilentlyContinue"
$Script:FailureCount = 0
$Script:PassCount = 0
$Script:WarnCount = 0

# Output formatting functions
function Write-Pass {
    param([string]$Message)
    Write-Host "[PASS] $Message" -ForegroundColor Green
    $Script:PassCount++
}

function Write-Fail {
    param([string]$Message)
    Write-Host "[FAIL] $Message" -ForegroundColor Red
    $Script:FailureCount++
}

function Write-Warn {
    param([string]$Message)
    Write-Host "[WARN] $Message" -ForegroundColor Yellow
    $Script:WarnCount++
}

function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Cyan
}

function Write-SectionHeader {
    param([string]$Title)
    Write-Host "`n============================================" -ForegroundColor Magenta
    Write-Host " $Title" -ForegroundColor Magenta
    Write-Host "============================================`n" -ForegroundColor Magenta
}

# Verify Azure connection
function Test-AzureConnection {
    try {
        $context = Get-AzContext -ErrorAction Stop
        if ($null -eq $context) {
            Write-Host "[ERROR] Not connected to Azure. Run 'Connect-AzAccount' first." -ForegroundColor Red
            exit 1
        }
        Write-Info "Connected to Azure Subscription: $($context.Subscription.Name) ($($context.Subscription.Id))"
        return $true
    }
    catch {
        Write-Host "[ERROR] Failed to get Azure context: $_" -ForegroundColor Red
        exit 1
    }
}

# Check if required modules are available
function Test-RequiredModules {
    Write-Info "Checking required PowerShell modules..."

    $requiredModules = @('Az.Accounts', 'Az.Resources')
    $missingModules = @()

    foreach ($module in $requiredModules) {
        if (-not (Get-Module -ListAvailable -Name $module)) {
            $missingModules += $module
        }
    }

    if ($missingModules.Count -gt 0) {
        Write-Host "[ERROR] Missing required modules: $($missingModules -join ', ')" -ForegroundColor Red
        Write-Host "Install with: Install-Module -Name $($missingModules -join ', ') -Force" -ForegroundColor Yellow
        exit 1
    }

    Write-Info "All required modules are available"
}

# AZ-IAM-01: Check MFA for privileged users
function Test-PrivilegedAccountMFA {
    Write-SectionHeader "AZ-IAM-01: Multi-Factor Authentication for Privileged Accounts"

    try {
        # Note: This requires Microsoft Graph PowerShell or Azure AD module
        # Using Az.Resources to check if  Microsoft Graph is available
        Write-Info "Checking for MFA enforcement via Conditional Access..."

        # Check if Conditional Access policies exist that require MFA for admins
        $caPolices = Get-AzResource -ResourceType "Microsoft.Authorization/policyAssignments" -ErrorAction SilentlyContinue

        if ($null -eq $caPolices) {
            Write-Warn "Unable to verify MFA status - requires Microsoft Graph PowerShell module or Azure AD module"
            Write-Info "Manual verification required: Check Entra ID > Security > Conditional Access"
            Write-Info "Verify policy exists requiring MFA for privileged roles"
            return
        }

        # For production use, integrate with Microsoft.Graph.Identity.SignIns module
        Write-Warn "Automated MFA check requires Microsoft Graph PowerShell module"
        Write-Info "Install with: Install-Module Microsoft.Graph -Scope CurrentUser"
        Write-Info "Manual check: Entra ID > Users > Per-user MFA or Conditional Access"
        Write-Info "CIS Control: 1.1.1, 1.1.2, 1.2.1"

    }
    catch {
        Write-Warn "Error checking MFA status: $_"
        Write-Info "Manual verification required via Azure Portal"
    }
}

# AZ-IAM-02: Check for permanent Global Administrator assignments
function Test-PermanentGlobalAdmins {
    Write-SectionHeader "AZ-IAM-02: No Permanent Global Administrator Assignments"

    try {
        Write-Info "Checking for permanent Global Administrator role assignments..."
        Write-Info "Note: Requires Azure AD/Entra ID permissions"

        # This check requires Azure AD module or Microsoft Graph
        # Placeholder for production implementation
        Write-Warn "Automated check requires Microsoft.Graph.Identity.DirectoryManagement module"
        Write-Info "Manual check:"
        Write-Info "  1. Navigate to Entra ID > Roles and administrators"
        Write-Info "  2. Select 'Global Administrator'"
        Write-Info "  3. Verify assignments are 'Eligible' (PIM) not 'Active' (permanent)"
        Write-Info "  4. Use Privileged Identity Management for just-in-time access"
        Write-Info "CIS Control: 1.1.3"

    }
    catch {
        Write-Warn "Error checking Global Administrator assignments: $_"
    }
}

# AZ-IAM-03: Check guest user restrictions
function Test-GuestUserRestrictions {
    Write-SectionHeader "AZ-IAM-03: Guest User Permissions Restricted"

    try {
        Write-Info "Checking guest user settings..."

        # This requires Azure AD/Microsoft Graph
        Write-Warn "Automated check requires Microsoft Graph module"
        Write-Info "Manual check:"
        Write-Info "  Navigate to: Entra ID > Users > User settings > External collaboration settings"
        Write-Info "  Verify:"
        Write-Info "    - Guest user permissions are limited: Yes"
        Write-Info "    - Members can invite: No"
        Write-Info "    - Guests can invite: No"
        Write-Info "CIS Control: 1.5, 1.7, 1.8, 1.9"

    }
    catch {
        Write-Warn "Error checking guest user restrictions: $_"
    }
}

# AZ-IAM-04: Check application registration settings
function Test-ApplicationRegistration {
    Write-SectionHeader "AZ-IAM-04: User Application Registration Disabled"

    try {
        Write-Info "Checking application registration settings..."

        Write-Warn "Automated check requires Microsoft Graph module"
        Write-Info "Manual check:"
        Write-Info "  Navigate to: Entra ID > Users > User settings"
        Write-Info "  Verify: Users can register applications: No"
        Write-Info "CIS Control: 1.4"

    }
    catch {
        Write-Warn "Error checking application registration settings: $_"
    }
}

# AZ-IAM-05: Check Azure RBAC assignments
function Test-RBACAssignments {
    Write-SectionHeader "AZ-IAM-05: Review RBAC Assignments"

    try {
        Write-Info "Analyzing RBAC role assignments..."

        $subscriptions = Get-AzSubscription -ErrorAction Stop

        foreach ($sub in $subscriptions) {
            Set-AzContext -SubscriptionId $sub.Id -ErrorAction SilentlyContinue | Out-Null
            Write-Info "Checking subscription: $($sub.Name)"

            # Get all role assignments
            $roleAssignments = Get-AzRoleAssignment -ErrorAction SilentlyContinue

            if ($roleAssignments) {
                # Check for overly permissive assignments
                $ownerAssignments = $roleAssignments | Where-Object { $_.RoleDefinitionName -eq "Owner" }
                $contributorAssignments = $roleAssignments | Where-Object { $_.RoleDefinitionName -eq "Contributor" }

                if ($ownerAssignments.Count -gt 5) {
                    Write-Warn "Found $($ownerAssignments.Count) Owner role assignments - review for least privilege"
                }

                if ($contributorAssignments.Count -gt 10) {
                    Write-Info "Found $($contributorAssignments.Count) Contributor role assignments"
                }

                # Check for user assignments (vs. group assignments)
                $userAssignments = $roleAssignments | Where-Object { $_.ObjectType -eq "User" }
                if ($userAssignments.Count -gt 0) {
                    Write-Info "Found $($userAssignments.Count) direct user role assignments"
                    Write-Info "Best practice: Assign roles to groups, not individual users"
                }

                Write-Pass "RBAC assignments reviewed for subscription: $($sub.Name)"
            }
            else {
                Write-Warn "Unable to retrieve role assignments for: $($sub.Name)"
            }
        }

    }
    catch {
        Write-Fail "Error checking RBAC assignments: $_"
    }
}

# AZ-IAM-06: Check for service principals with expiring credentials
function Test-ServicePrincipalCredentials {
    Write-SectionHeader "AZ-IAM-06: Service Principal Credential Management"

    try {
        Write-Info "Checking service principal credentials..."

        Write-Warn "Service principal credential check requires Microsoft Graph module"
        Write-Info "Manual check:"
        Write-Info "  1. Navigate to: Entra ID > App registrations"
        Write-Info "  2. Review each application"
        Write-Info "  3. Check Certificates & secrets"
        Write-Info "  4. Verify secrets have expiration dates set"
        Write-Info "  5. Rotate credentials that are > 90 days old"

    }
    catch {
        Write-Warn "Error checking service principal credentials: $_"
    }
}

# AZ-IAM-07: Check subscription ownership
function Test-SubscriptionOwnership {
    Write-SectionHeader "AZ-IAM-07: Subscription Ownership Review"

    try {
        $subscriptions = Get-AzSubscription -ErrorAction Stop

        foreach ($sub in $subscriptions) {
            Set-AzContext -SubscriptionId $sub.Id -ErrorAction SilentlyContinue | Out-Null

            Write-Info "Reviewing subscription: $($sub.Name)"

            # Get subscription-level Owner assignments
            $owners = Get-AzRoleAssignment -RoleDefinitionName "Owner" -Scope "/subscriptions/$($sub.Id)" -ErrorAction SilentlyContinue

            if ($owners.Count -eq 0) {
                Write-Fail "No owners assigned to subscription: $($sub.Name)"
            }
            elseif ($owners.Count -gt 5) {
                Write-Warn "Subscription has $($owners.Count) owners - review for least privilege"
            }
            else {
                Write-Pass "Subscription $($sub.Name) has $($owners.Count) owner(s)"
            }
        }

    }
    catch {
        Write-Fail "Error checking subscription ownership: $_"
    }
}

# Main execution
function Main {
    Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║   Azure IAM Security Hardening Checks                        ║" -ForegroundColor Cyan
    Write-Host "║   CIS Microsoft Azure Foundations Benchmark v2.0.0           ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan

    # Verify prerequisites
    Test-RequiredModules
    Test-AzureConnection

    Write-Info "Starting IAM security checks...`n"

    # Run all checks
    Test-PrivilegedAccountMFA
    Test-PermanentGlobalAdmins
    Test-GuestUserRestrictions
    Test-ApplicationRegistration
    Test-RBACAssignments
    Test-ServicePrincipalCredentials
    Test-SubscriptionOwnership

    # Summary
    Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║   IAM Security Check Summary                                  ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan

    Write-Host "Results:" -ForegroundColor White
    Write-Host "  PASS: $Script:PassCount" -ForegroundColor Green
    Write-Host "  FAIL: $Script:FailureCount" -ForegroundColor Red
    Write-Host "  WARN: $Script:WarnCount" -ForegroundColor Yellow

    $total = $Script:PassCount + $Script:FailureCount + $Script:WarnCount
    if ($total -gt 0) {
        $complianceRate = [math]::Round(($Script:PassCount / $total) * 100, 2)
        Write-Host "`nCompliance Rate: $complianceRate%" -ForegroundColor $(if ($complianceRate -ge 90) { "Green" } elseif ($complianceRate -ge 70) { "Yellow" } else { "Red" })
    }

    Write-Host "`nNote: Some checks require Microsoft Graph PowerShell module for full automation." -ForegroundColor Yellow
    Write-Host "Install with: Install-Module Microsoft.Graph -Scope CurrentUser`n" -ForegroundColor Yellow

    # Exit code based on failures
    if ($Script:FailureCount -gt 0) {
        exit 1
    }
    exit 0
}

# Execute main function
Main
