# Get-ShareInventory.ps1
# Purpose : Enumerate SMB shares and flag overly permissive ACLs
# Requires: Admin rights (MDE Live Response runs as SYSTEM — satisfied)
# Usage   : Upload to MDE Live Response library, then in the session:
#             run Get-ShareInventory.ps1
#             getfile C:\Windows\Temp\share_inventory_COMPUTERNAME.csv

$ErrorActionPreference = 'Stop'
$OutputFile = "C:\Windows\Temp\share_inventory_$($env:COMPUTERNAME).csv"

# Admin shares to skip — always present, not relevant to this assessment
$AdminShares = @('C$','D$','E$','F$','G$','ADMIN$','IPC$','print$','SYSVOL','NETLOGON')

# Groups whose Allow access on a share is a risk signal
$RiskyAccounts = @(
    'everyone',
    'authenticated users',
    'nt authority\authenticated users',
    'domain users'
)

Write-Host "`n=== SMB Share Inventory: $($env:COMPUTERNAME) ===" -ForegroundColor Cyan
Write-Host "Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n"

$AllShares    = Get-SmbShare
$BizShares    = $AllShares | Where-Object { $AdminShares -notcontains $_.Name }

Write-Host "Total shares   : $($AllShares.Count)"
Write-Host "Admin (skipped): $($AllShares.Count - $BizShares.Count)"
Write-Host "Business shares: $($BizShares.Count)`n"

$Results = foreach ($Share in $BizShares) {
    Write-Host "[$($Share.Name)] $($Share.Path)" -ForegroundColor Yellow

    $Aces = Get-SmbShareAccess -Name $Share.Name -ErrorAction SilentlyContinue

    foreach ($Ace in $Aces) {
        $AccountLower = $Ace.AccountName.ToLower()
        $IsBroadGroup = $RiskyAccounts | Where-Object {
            $AccountLower -eq $_ -or $AccountLower.EndsWith("\$_")
        }
        $IsRisky = ($null -ne $IsBroadGroup) -and ($Ace.AccessControlType -eq 'Allow')
        $Tag     = if ($IsRisky) { ' *** RISKY ***' } else { '' }

        Write-Host ("  {0,-40} {1,-10} {2}{3}" -f `
            $Ace.AccountName, $Ace.AccessRight, $Ace.AccessControlType, $Tag)

        [PSCustomObject]@{
            ComputerName      = $env:COMPUTERNAME
            ShareName         = $Share.Name
            SharePath         = $Share.Path
            AccountName       = $Ace.AccountName
            AccessRight       = $Ace.AccessRight
            AccessControlType = $Ace.AccessControlType
            IsRisky           = $IsRisky
            RiskyReason       = if ($IsRisky) {
                                    "'$($Ace.AccountName)' has $($Ace.AccessRight) access"
                                } else { '' }
        }
    }
    Write-Host ''
}

$RiskyCount = ($Results | Where-Object { $_.IsRisky }).Count
Write-Host "=== SUMMARY ===" -ForegroundColor Cyan
Write-Host "Risky ACEs found: $RiskyCount"

$Results | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
Write-Host "CSV saved : $OutputFile"
Write-Host "Download  : getfile $OutputFile"
