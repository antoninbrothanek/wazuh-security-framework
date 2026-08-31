#requires -Version 5.1

<#
.SYNOPSIS
    Removes legacy WSF Event Channel registry-policy values from an existing GPO.

.DESCRIPTION
    Early WSF telemetry-provisioning builds wrote Enabled and MaxSize directly
    below the WINEVT channel-registration registry path. Pilot validation showed
    that this is not a safe Group Policy ownership boundary: MaxSize caused the
    NTLM Operational channel configuration API to fail with Win32 error 234 and
    the value remained tattooed locally after the GPO was unlinked.

    This migration helper removes ONLY the two legacy WSF registry-policy values
    from the GPO. It never changes GPO links and never runs gpupdate.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $false)]
    [string]$GpoName = 'Wazuh Domain Controller Enable Logs Policy'
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

if ($PSVersionTable.PSEdition -eq 'Core') {
    $windowsPowerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $args = @('-NoProfile','-ExecutionPolicy','Bypass','-File',$PSCommandPath,'-GpoName',$GpoName)
    if ($WhatIfPreference) { $args += '-WhatIf' }
    Write-Host 'WSF: Relaunching migration helper in Windows PowerShell 5.1...'
    & $windowsPowerShell @args
    exit $LASTEXITCODE
}

Import-Module ActiveDirectory -ErrorAction Stop
Import-Module GroupPolicy -ErrorAction Stop

$domain = Get-ADDomain -ErrorAction Stop
$domainName = [string]$domain.DNSRoot
$pdcName = [string]$domain.PDCEmulator
$gpo = Get-GPO -Name $GpoName -Domain $domainName -Server $pdcName -ErrorAction Stop

$channelKey = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-NTLM/Operational'

Write-Host '===== WSF LEGACY WINEVT GPO CLEANUP ====='
Write-Host ('GPO       : {0}' -f $gpo.DisplayName)
Write-Host ('GPO ID    : {0}' -f $gpo.Id)
Write-Host ('Domain    : {0}' -f $domainName)
Write-Host ('Write DC  : {0}' -f $pdcName)
Write-Host 'Values    : Enabled, MaxSize'
Write-Host 'GPO links : NOT MODIFIED'
Write-Host 'gpupdate  : NOT USED'

if ($PSCmdlet.ShouldProcess($gpo.DisplayName, 'Remove legacy WSF WINEVT registry-policy values Enabled and MaxSize')) {
    foreach ($valueName in @('Enabled','MaxSize')) {
        try {
            Remove-GPRegistryValue -Guid $gpo.Id -Domain $domainName -Server $pdcName `
                -Key $channelKey -ValueName $valueName -Confirm:$false -ErrorAction Stop | Out-Null
            Write-Host ('{0,-10}: REMOVED' -f $valueName)
        }
        catch {
            if ($_.Exception.Message -match '(?i)not found|does not exist|cannot find') {
                Write-Host ('{0,-10}: ABSENT' -f $valueName)
            }
            else {
                throw
            }
        }
    }

    $report = Get-GPOReport -Guid $gpo.Id -Domain $domainName -Server $pdcName -ReportType Xml -ErrorAction Stop
    if ($report -match [regex]::Escape($channelKey)) {
        throw 'Verification failed: legacy WINEVT channel registry policy is still present in the GPO report.'
    }

    Write-Host ''
    Write-Host 'RESULT: PASS - legacy WINEVT registry-policy values are absent from the GPO.'
}
else {
    Write-Host ''
    Write-Host 'RESULT: WHATIF - no GPO content was changed.'
}
