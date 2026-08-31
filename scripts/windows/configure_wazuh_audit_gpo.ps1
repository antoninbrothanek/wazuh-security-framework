#requires -Version 5.1

<#
.SYNOPSIS
    Configures an existing Wazuh Security Framework audit GPO from the portable
    Windows audit policy XML definition.

.DESCRIPTION
    This is the configuration stage that follows create_wazuh_audit_gpo.ps1.
    It configures an existing WSF GPO but NEVER creates a GPO link and NEVER
    invokes gpupdate.

    The writer uses native Group Policy data stores where required:
      - Security Options: Security Settings template (GptTmpl.inf)
      - Advanced Audit Policy: Advanced Audit Policy audit.csv
      - SpecialGroups: Group Policy Preferences Registry item
      - Event-channel prerequisites: registry-based computer policy

    The script performs all validation before writing, creates a GPO backup,
    writes through one domain controller, and registers the Security and
    Advanced Audit Policy client-side extensions so the GPO revision is updated.

    PowerShell 7 is supported as a launcher. The script relaunches itself in
    Windows PowerShell 5.1 because the Microsoft Group Policy management API is
    a Windows PowerShell / GPMC component.

    A linked GPO is refused by default. -AllowLinkedGpo is an explicit safety
    acknowledgement; it does not create or change links.

.PARAMETER PolicyFile
    Path to policies/windows/domain-controller-audit.xml or another compatible
    WSF Windows audit policy XML file.

.PARAMETER GpoName
    Optional override for Metadata/Name.

.PARAMETER AllowLinkedGpo
    Permit configuration of a GPO that already has one or more links. Use only
    when the existing links and their impact are understood.

.EXAMPLE
    .\configure_wazuh_audit_gpo.ps1 `
        -PolicyFile ..\..\policies\windows\domain-controller-audit.xml `
        -WhatIf

.EXAMPLE
    .\configure_wazuh_audit_gpo.ps1 `
        -PolicyFile ..\..\policies\windows\domain-controller-audit.xml `
        -AllowLinkedGpo `
        -WhatIf

.NOTES
    Wazuh Security Framework
    Phase: Windows telemetry provisioning / GPO configuration writer
    Safety boundary: existing GPO only; never links; never runs gpupdate.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$PolicyFile,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$GpoName,

    [Parameter(Mandatory = $false)]
    [switch]$AllowLinkedGpo
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Write-Section {
    param([Parameter(Mandatory = $true)][string]$Title)
    Write-Host ''
    Write-Host ('===== {0} =====' -f $Title)
}

function Resolve-PolicyPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return (Resolve-Path -LiteralPath $Path).Path
    }

    return (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot $Path)).Path
}

function ConvertTo-Bool {
    param(
        [Parameter(Mandatory = $true)][object]$Value,
        [Parameter(Mandatory = $true)][string]$Context
    )

    switch (([string]$Value).ToLowerInvariant()) {
        'true'  { return $true }
        'false' { return $false }
        default { throw "Invalid Boolean value '$Value' in $Context." }
    }
}

function Get-RequiredXmlNode {
    param(
        [Parameter(Mandatory = $true)][System.Xml.XmlNode]$Parent,
        [Parameter(Mandatory = $true)][string]$XPath,
        [Parameter(Mandatory = $true)][string]$Context
    )

    $node = $Parent.SelectSingleNode($XPath)
    if ($null -eq $node) {
        throw "Missing required XML element: $Context ($XPath)."
    }
    return $node
}

function Get-RequiredAttribute {
    param(
        [Parameter(Mandatory = $true)][System.Xml.XmlNode]$Node,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Context
    )

    if ($null -eq $Node.Attributes[$Name] -or [string]::IsNullOrWhiteSpace($Node.Attributes[$Name].Value)) {
        throw "Missing required attribute '$Name' in $Context."
    }
    return $Node.Attributes[$Name].Value
}

function ConvertTo-SidString {
    param(
        [Parameter(Mandatory = $true)][object]$Sid,
        [Parameter(Mandatory = $true)][string]$Context
    )

    if ($null -eq $Sid) {
        throw "SID is unavailable for $Context."
    }

    $sidText = if ($null -ne $Sid.PSObject.Properties['Value']) {
        [string]$Sid.Value
    }
    else {
        [string]$Sid
    }

    if ($sidText -notmatch '^S-1-[0-9-]+$') {
        throw "Invalid SID '$sidText' returned for $Context."
    }
    return $sidText
}

function Get-AuditSetting {
    param(
        [Parameter(Mandatory = $true)][bool]$Success,
        [Parameter(Mandatory = $true)][bool]$Failure
    )

    if ($Success -and $Failure) {
        return [pscustomobject]@{ Inclusion = 'Success and Failure'; Value = 3 }
    }
    if ($Success) {
        return [pscustomobject]@{ Inclusion = 'Success'; Value = 1 }
    }
    if ($Failure) {
        return [pscustomobject]@{ Inclusion = 'Failure'; Value = 2 }
    }
    return [pscustomobject]@{ Inclusion = 'No Auditing'; Value = 0 }
}

function Write-Utf8NoBom {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Content
    )

    $encoding = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Content, $encoding)
}

function Register-GpoExtension {
    param(
        [Parameter(Mandatory = $true)][System.DirectoryServices.ActiveDirectory.DomainController]$DomainController,
        [Parameter(Mandatory = $true)][guid]$GpoId,
        [Parameter(Mandatory = $true)][guid]$ClientSideExtension,
        [Parameter(Mandatory = $true)][guid]$Editor
    )

    $nativeGpo = New-Object Microsoft.GroupPolicy.GroupPolicyObject
    try {
        $nativeGpo.OpenDSGpo($DomainController, $GpoId, $false, $false)
        $nativeGpo.Save($true, $true, $ClientSideExtension, $Editor)
    }
    finally {
        $nativeGpo.Dispose()
    }
}

# PowerShell 7 can import GroupPolicy through WinPSCompat, but the native GPMC
# API used to register non-registry CSEs must run in Windows PowerShell.
if ($PSVersionTable.PSEdition -eq 'Core') {
    $windowsPowerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if (-not (Test-Path -LiteralPath $windowsPowerShell)) {
        throw "Windows PowerShell 5.1 was not found at '$windowsPowerShell'."
    }

    $relaunchArgs = @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', $PSCommandPath,
        '-PolicyFile', $PolicyFile
    )
    if (-not [string]::IsNullOrWhiteSpace($GpoName)) {
        $relaunchArgs += @('-GpoName', $GpoName)
    }
    if ($AllowLinkedGpo) {
        $relaunchArgs += '-AllowLinkedGpo'
    }
    if ($WhatIfPreference) {
        $relaunchArgs += '-WhatIf'
    }

    Write-Host 'WSF: Relaunching GPO configuration writer in Windows PowerShell 5.1...'
    & $windowsPowerShell @relaunchArgs
    exit $LASTEXITCODE
}

try {
    Write-Section 'WSF AUDIT GPO CONFIGURATION'

    $resolvedPolicyFile = Resolve-PolicyPath -Path $PolicyFile
    [xml]$policy = Get-Content -LiteralPath $resolvedPolicyFile -Raw

    $root = $policy.SelectSingleNode('/WazuhSecurityFrameworkPolicy')
    if ($null -eq $root) {
        throw 'Root element WazuhSecurityFrameworkPolicy was not found.'
    }

    $schemaVersion = Get-RequiredAttribute -Node $root -Name 'schemaVersion' -Context 'WazuhSecurityFrameworkPolicy'
    $role = Get-RequiredAttribute -Node $root -Name 'role' -Context 'WazuhSecurityFrameworkPolicy'
    if ($schemaVersion -ne '1.0') { throw "Unsupported schemaVersion '$schemaVersion'." }
    if ($role -ne 'DomainController') { throw "Unsupported role '$role'." }

    $metadata = Get-RequiredXmlNode -Parent $root -XPath 'Metadata' -Context 'Metadata'
    $nameNode = Get-RequiredXmlNode -Parent $metadata -XPath 'Name' -Context 'Metadata/Name'
    $autoLink = ConvertTo-Bool -Value (Get-RequiredXmlNode -Parent $metadata -XPath 'AutoLink' -Context 'Metadata/AutoLink').InnerText -Context 'Metadata/AutoLink'

    $effectiveGpoName = [string]$nameNode.InnerText
    if (-not [string]::IsNullOrWhiteSpace($GpoName)) { $effectiveGpoName = $GpoName }

    $deployment = Get-RequiredXmlNode -Parent $root -XPath 'Deployment' -Context 'Deployment'
    $linkGpo = ConvertTo-Bool -Value (Get-RequiredXmlNode -Parent $deployment -XPath 'LinkGpo' -Context 'Deployment/LinkGpo').InnerText -Context 'Deployment/LinkGpo'
    $requireExplicitLinkTarget = ConvertTo-Bool -Value (Get-RequiredXmlNode -Parent $deployment -XPath 'RequireExplicitLinkTarget' -Context 'Deployment/RequireExplicitLinkTarget').InnerText -Context 'Deployment/RequireExplicitLinkTarget'

    if ($autoLink -or $linkGpo) {
        throw 'Safety check failed: automatic GPO linking must remain disabled.'
    }
    if (-not $requireExplicitLinkTarget) {
        throw 'Safety check failed: RequireExplicitLinkTarget must be true.'
    }

    Write-Host ('Policy file : {0}' -f $resolvedPolicyFile)
    Write-Host ('Schema      : {0}' -f $schemaVersion)
    Write-Host ('Role        : {0}' -f $role)
    Write-Host ('GPO name    : {0}' -f $effectiveGpoName)
    Write-Host 'Auto-link   : disabled'

    Write-Section 'MODULES AND DOMAIN CONTROLLER'
    Import-Module ActiveDirectory -ErrorAction Stop
    Import-Module GroupPolicy -ErrorAction Stop

    try {
        Add-Type -AssemblyName Microsoft.GroupPolicy.Management.Interop -ErrorAction Stop
    }
    catch {
        throw "Microsoft Group Policy management API could not be loaded. Install GPMC/RSAT Group Policy Management. Details: $($_.Exception.Message)"
    }

    $domain = Get-ADDomain -ErrorAction Stop
    $forest = Get-ADForest -ErrorAction Stop
    $rootDomain = Get-ADDomain -Identity $forest.RootDomain -ErrorAction Stop

    $domainName = [string]$domain.DNSRoot
    $pdcName = [string]$domain.PDCEmulator
    $domainSid = ConvertTo-SidString -Sid $domain.DomainSID -Context 'current domain'
    $forestRootSid = ConvertTo-SidString -Sid $rootDomain.DomainSID -Context 'forest root domain'

    $nativeDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain(
        (New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $domainName))
    )
    $nativeDc = $nativeDomain.FindDomainController(
        (New-Object System.DirectoryServices.ActiveDirectory.LocatorOptions)
    )

    # Prefer the PDC for both AD metadata and SYSVOL writes. Resolve it directly
    # for the Microsoft.GroupPolicy API instead of relying on DFS referral.
    if ($nativeDc.Name -ne $pdcName) {
        $nativeDc.Dispose()
        $dcContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('DirectoryServer', $pdcName)
        $nativeDc = [System.DirectoryServices.ActiveDirectory.DomainController]::GetDomainController($dcContext)
    }

    Write-Host ('Domain      : {0}' -f $domainName)
    Write-Host ('Write DC    : {0}' -f $pdcName)
    Write-Host ('Shell       : Windows PowerShell {0}' -f $PSVersionTable.PSVersion)

    Write-Section 'TARGET GPO'
    $gpo = Get-GPO -Name $effectiveGpoName -Domain $domainName -Server $pdcName -ErrorAction Stop
    $gpoId = [guid]$gpo.Id
    $gpoGuidBraced = '{' + $gpoId.ToString().ToUpperInvariant() + '}'

    Write-Host ('Display name : {0}' -f $gpo.DisplayName)
    Write-Host ('GPO ID       : {0}' -f $gpoId)
    Write-Host ('GPO status   : {0}' -f $gpo.GpoStatus)

    [xml]$gpoReport = Get-GPOReport -Guid $gpoId -Domain $domainName -Server $pdcName -ReportType Xml -ErrorAction Stop
    $linkNodes = @($gpoReport.SelectNodes("//*[local-name()='LinksTo']"))
    $linkCount = $linkNodes.Count

    Write-Host ('Existing links : {0}' -f $linkCount)
    if ($linkCount -gt 0 -and -not $AllowLinkedGpo) {
        throw "Target GPO already has $linkCount link(s). Refusing to configure it without explicit -AllowLinkedGpo acknowledgement."
    }
    if ($linkCount -gt 0) {
        Write-Warning 'Target GPO is linked. Configuration may become effective through normal Group Policy refresh after a real write.'
    }

    # ----------------------------
    # Parse and validate all inputs
    # ----------------------------
    Write-Section 'CONFIGURATION PLAN'

    $securityOptions = Get-RequiredXmlNode -Parent $root -XPath 'SecurityOptions' -Context 'SecurityOptions'
    $forceAdvancedNode = Get-RequiredXmlNode -Parent $securityOptions -XPath 'ForceAdvancedAuditPolicy' -Context 'SecurityOptions/ForceAdvancedAuditPolicy'
    $forceAdvanced = ConvertTo-Bool -Value (Get-RequiredAttribute -Node $forceAdvancedNode -Name 'enabled' -Context 'ForceAdvancedAuditPolicy') -Context 'ForceAdvancedAuditPolicy@enabled'

    $ntlm = Get-RequiredXmlNode -Parent $securityOptions -XPath 'NTLMAuditing' -Context 'SecurityOptions/NTLMAuditing'
    $incomingMode = Get-RequiredAttribute -Node (Get-RequiredXmlNode -Parent $ntlm -XPath 'Incoming' -Context 'NTLMAuditing/Incoming') -Name 'mode' -Context 'NTLMAuditing/Incoming'
    $domainMode = Get-RequiredAttribute -Node (Get-RequiredXmlNode -Parent $ntlm -XPath 'DomainAuthentication' -Context 'NTLMAuditing/DomainAuthentication') -Name 'mode' -Context 'NTLMAuditing/DomainAuthentication'
    $outgoingMode = Get-RequiredAttribute -Node (Get-RequiredXmlNode -Parent $ntlm -XPath 'Outgoing' -Context 'NTLMAuditing/Outgoing') -Name 'mode' -Context 'NTLMAuditing/Outgoing'

    if ($incomingMode -ne 'AuditAllAccounts') { throw "Unsupported NTLM incoming mode '$incomingMode'." }
    if ($domainMode -ne 'AuditAll') { throw "Unsupported NTLM domain mode '$domainMode'." }
    if ($outgoingMode -ne 'AuditAll') { throw "Unsupported NTLM outgoing mode '$outgoingMode'." }

    $securityRegistryValues = @(
        [pscustomobject]@{ Key = 'MACHINE\System\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy'; Value = $(if ($forceAdvanced) { 1 } else { 0 }) },
        [pscustomobject]@{ Key = 'MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\AuditReceivingNTLMTraffic'; Value = 2 },
        [pscustomobject]@{ Key = 'MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\RestrictSendingNTLMTraffic'; Value = 1 },
        [pscustomobject]@{ Key = 'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\AuditNTLMInDomain'; Value = 7 }
    )

    $auditGuidMap = @{
        'Credential Validation'               = '{0CCE923F-69AE-11D9-BED3-505054503030}'
        'Kerberos Authentication Service'     = '{0CCE9242-69AE-11D9-BED3-505054503030}'
        'Kerberos Service Ticket Operations'  = '{0CCE9240-69AE-11D9-BED3-505054503030}'
        'Other Account Logon Events'          = '{0CCE9241-69AE-11D9-BED3-505054503030}'
        'Application Group Management'        = '{0CCE9239-69AE-11D9-BED3-505054503030}'
        'Computer Account Management'         = '{0CCE9236-69AE-11D9-BED3-505054503030}'
        'Distribution Group Management'       = '{0CCE9238-69AE-11D9-BED3-505054503030}'
        'Other Account Management Events'     = '{0CCE923A-69AE-11D9-BED3-505054503030}'
        'Security Group Management'           = '{0CCE9237-69AE-11D9-BED3-505054503030}'
        'User Account Management'             = '{0CCE9235-69AE-11D9-BED3-505054503030}'
        'Process Creation'                    = '{0CCE922B-69AE-11D9-BED3-505054503030}'
        'Directory Service Changes'           = '{0CCE923C-69AE-11D9-BED3-505054503030}'
        'Account Lockout'                     = '{0CCE9217-69AE-11D9-BED3-505054503030}'
        'Logoff'                              = '{0CCE9216-69AE-11D9-BED3-505054503030}'
        'Logon'                               = '{0CCE9215-69AE-11D9-BED3-505054503030}'
        'Special Logon'                       = '{0CCE921B-69AE-11D9-BED3-505054503030}'
        'Audit Policy Change'                 = '{0CCE922F-69AE-11D9-BED3-505054503030}'
        'Authentication Policy Change'        = '{0CCE9230-69AE-11D9-BED3-505054503030}'
        'Authorization Policy Change'         = '{0CCE9231-69AE-11D9-BED3-505054503030}'
        'Sensitive Privilege Use'             = '{0CCE9228-69AE-11D9-BED3-505054503030}'
        'Security System Extension'           = '{0CCE9211-69AE-11D9-BED3-505054503030}'
    }

    $auditRows = @()
    $advancedAudit = Get-RequiredXmlNode -Parent $root -XPath 'AdvancedAuditPolicy' -Context 'AdvancedAuditPolicy'
    foreach ($category in $advancedAudit.SelectNodes('Category')) {
        foreach ($subcategory in $category.SelectNodes('Subcategory')) {
            $name = Get-RequiredAttribute -Node $subcategory -Name 'name' -Context 'AdvancedAuditPolicy/Subcategory'
            if (-not $auditGuidMap.ContainsKey($name)) {
                throw "No approved Advanced Audit Policy GUID mapping exists for '$name'."
            }
            $success = ConvertTo-Bool -Value (Get-RequiredAttribute -Node $subcategory -Name 'success' -Context "Subcategory '$name'") -Context "$name@success"
            $failure = ConvertTo-Bool -Value (Get-RequiredAttribute -Node $subcategory -Name 'failure' -Context "Subcategory '$name'") -Context "$name@failure"
            $setting = Get-AuditSetting -Success $success -Failure $failure
            $auditRows += [pscustomobject]@{
                Name      = $name
                Guid      = $auditGuidMap[$name]
                Inclusion = $setting.Inclusion
                Value     = $setting.Value
            }
        }
    }
    if ($auditRows.Count -ne 21) {
        throw "Expected 21 Advanced Audit Policy rows for schema 1.0 DomainController policy; found $($auditRows.Count)."
    }

    $specialGroupsNode = Get-RequiredXmlNode -Parent $root -XPath 'SpecialGroups' -Context 'SpecialGroups'
    $resolvedSids = @()
    foreach ($group in $specialGroupsNode.SelectNodes('Group')) {
        $type = Get-RequiredAttribute -Node $group -Name 'type' -Context 'SpecialGroups/Group'
        $name = Get-RequiredAttribute -Node $group -Name 'name' -Context 'SpecialGroups/Group'
        switch ($type) {
            'WellKnownSid' {
                $sid = Get-RequiredAttribute -Node $group -Name 'sid' -Context "SpecialGroups/Group '$name'"
                if ($sid -notmatch '^S-1-[0-9-]+$') { throw "Invalid SID '$sid'." }
                $resolvedSids += $sid
            }
            'DomainRid' {
                $rid = Get-RequiredAttribute -Node $group -Name 'rid' -Context "SpecialGroups/Group '$name'"
                if ($rid -notmatch '^\d+$') { throw "Invalid RID '$rid'." }
                $resolvedSids += "$domainSid-$rid"
            }
            'ForestRootDomainRid' {
                $rid = Get-RequiredAttribute -Node $group -Name 'rid' -Context "SpecialGroups/Group '$name'"
                if ($rid -notmatch '^\d+$') { throw "Invalid RID '$rid'." }
                $resolvedSids += "$forestRootSid-$rid"
            }
            default { throw "Unsupported SpecialGroups type '$type'." }
        }
    }
    if ($resolvedSids.Count -ne 4) { throw "Expected 4 SpecialGroups entries; found $($resolvedSids.Count)." }
    $specialGroupsValue = $resolvedSids -join ';'

    $eventChannels = @()
    $eventChannelsNode = Get-RequiredXmlNode -Parent $root -XPath 'EventChannels' -Context 'EventChannels'
    foreach ($channel in $eventChannelsNode.SelectNodes('Channel')) {
        $channelName = Get-RequiredAttribute -Node $channel -Name 'name' -Context 'EventChannels/Channel'
        $enabled = ConvertTo-Bool -Value (Get-RequiredAttribute -Node $channel -Name 'enabled' -Context "EventChannels/Channel '$channelName'") -Context "$channelName@enabled"
        $minimumSizeMB = $null
        if ($null -ne $channel.Attributes['minimumSizeMB']) {
            [int]$parsedSize = 0
            if (-not [int]::TryParse($channel.Attributes['minimumSizeMB'].Value, [ref]$parsedSize) -or $parsedSize -le 0) {
                throw "Invalid minimumSizeMB for '$channelName'."
            }
            $minimumSizeMB = $parsedSize
        }
        $eventChannels += [pscustomobject]@{ Name = $channelName; Enabled = $enabled; MinimumSizeMB = $minimumSizeMB }
    }

    $unsupportedChannels = @($eventChannels | Where-Object { $_.Name -notin @('Security', 'Microsoft-Windows-NTLM/Operational') })
    if ($unsupportedChannels.Count -gt 0) {
        throw "Unsupported event channel '$($unsupportedChannels[0].Name)'."
    }

    Write-Host ('Security options          : {0}' -f $securityRegistryValues.Count)
    Write-Host ('Advanced audit settings   : {0}' -f $auditRows.Count)
    Write-Host ('Special groups            : {0}' -f $resolvedSids.Count)
    Write-Host ('Event channels            : {0}' -f $eventChannels.Count)
    Write-Host 'GPO link operations       : NONE'
    Write-Host 'gpupdate                  : NOT USED'

    # Build exact native file payloads before ShouldProcess.
    $securityLines = @(
        '[Unicode]',
        'Unicode=yes',
        '[Version]',
        'signature="$CHICAGO$"',
        'Revision=1',
        '[Registry Values]'
    )
    foreach ($entry in $securityRegistryValues) {
        $securityLines += ('{0}=4,{1}' -f $entry.Key, $entry.Value)
    }
    $securityTemplate = ($securityLines -join "`r`n") + "`r`n"

    # MS-GPAC 2.2 is not generic RFC-style CSV. Some fields permit quoted
    # strings, but Policy Target, Subcategory GUID and Setting Value have strict
    # grammar and must not be serialized as quoted CSV fields. Keep the payload
    # deliberately simple and ASCII; none of the approved WSF names contain a
    # comma, so quoting is unnecessary.
    $auditLines = @('Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value')
    foreach ($row in $auditRows) {
        $auditLines += ('WSF,System,{0},{1},{2},,{3}' -f $row.Name, $row.Guid, $row.Inclusion, $row.Value)
    }
    $auditCsv = ($auditLines -join "`r`n") + "`r`n"

    $machineRoot = "\\$pdcName\SYSVOL\$domainName\Policies\$gpoGuidBraced\Machine"
    $securityDir = Join-Path $machineRoot 'Microsoft\Windows NT\SecEdit'
    $securityFile = Join-Path $securityDir 'GptTmpl.inf'
    $auditDir = Join-Path $machineRoot 'Microsoft\Windows NT\Audit'
    $auditFile = Join-Path $auditDir 'audit.csv'

    Write-Section 'WRITE SAFETY'
    Write-Host ('SYSVOL target             : {0}' -f $machineRoot)
    Write-Host ('GPO linked                : {0}' -f $(if ($linkCount -gt 0) { 'YES' } else { 'NO' }))
    Write-Host ('Linked-GPO acknowledgement: {0}' -f $AllowLinkedGpo.IsPresent)
    Write-Host 'Backup before write       : YES'
    Write-Host 'New-GPLink                : NOT USED'
    Write-Host 'gpupdate                  : NOT USED'

    $targetDescription = "existing GPO '$effectiveGpoName' ($gpoId) in domain '$domainName'"
    if (-not $PSCmdlet.ShouldProcess($targetDescription, 'Configure WSF audit telemetry policy')) {
        Write-Section 'RESULT'
        Write-Host 'Security Options          : NOT PERFORMED'
        Write-Host 'Advanced Audit Policy     : NOT PERFORMED'
        Write-Host 'SpecialGroups             : NOT PERFORMED'
        Write-Host 'Event Channels            : NOT PERFORMED'
        Write-Host 'GPO link operation        : NOT PERFORMED'
        Write-Host 'Production changes        : NONE'
        Write-Host ''
        Write-Host 'RESULT: WHATIF/PREVIEW validation passed. No GPO content was changed.'
        exit 0
    }

    Write-Section 'BACKUP'
    $backupRoot = Join-Path $env:TEMP ('WSF-GPO-Backup-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
    New-Item -ItemType Directory -Path $backupRoot -Force | Out-Null
    Backup-GPO -Guid $gpoId -Domain $domainName -Server $pdcName -Path $backupRoot -ErrorAction Stop | Out-Null
    Write-Host ('Backup path : {0}' -f $backupRoot)

    Write-Section 'WRITE SECURITY OPTIONS'
    New-Item -ItemType Directory -Path $securityDir -Force | Out-Null
    Write-Utf8NoBom -Path $securityFile -Content $securityTemplate
    Register-GpoExtension -DomainController $nativeDc -GpoId $gpoId `
        -ClientSideExtension ([guid]'{827D319E-6EAC-11D2-A4EA-00C04F79F83A}') `
        -Editor ([guid]'{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}')
    Write-Host 'Security Settings template : WRITTEN'

    Write-Section 'WRITE ADVANCED AUDIT POLICY'
    New-Item -ItemType Directory -Path $auditDir -Force | Out-Null
    Write-Utf8NoBom -Path $auditFile -Content $auditCsv
    Register-GpoExtension -DomainController $nativeDc -GpoId $gpoId `
        -ClientSideExtension ([guid]'{F3CCC681-B74C-4060-9F26-CD84525DCA2A}') `
        -Editor ([guid]'{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}')
    Write-Host ('Advanced Audit rows       : {0} WRITTEN' -f $auditRows.Count)

    Write-Section 'WRITE SPECIAL GROUPS'
    # Match the reference deployment semantics: GPP Registry / Update.
    Set-GPPrefRegistryValue -Guid $gpoId -Domain $domainName -Server $pdcName `
        -Context Computer -Action Update `
        -Key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\Audit' `
        -ValueName 'SpecialGroups' -Type String -Value $specialGroupsValue `
        -Confirm:$false -ErrorAction Stop | Out-Null
    Write-Host 'SpecialGroups preference  : WRITTEN'

    Write-Section 'WRITE EVENT CHANNELS'
    foreach ($channel in $eventChannels) {
        if ($channel.Name -eq 'Security') {
            # Security is a built-in mandatory Windows event channel. The XML
            # declaration is a prerequisite assertion; no custom registry write
            # is required when only enabled=true is requested.
            if (-not $channel.Enabled) {
                throw 'WSF does not support disabling the Security event channel.'
            }
            Write-Host 'Security                                      : prerequisite asserted; no custom write'
            continue
        }

        if ($channel.Name -eq 'Microsoft-Windows-NTLM/Operational') {
            $channelKey = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-NTLM/Operational'
            Set-GPRegistryValue -Guid $gpoId -Domain $domainName -Server $pdcName `
                -Key $channelKey -ValueName 'Enabled' -Type DWord `
                -Value ([int]$(if ($channel.Enabled) { 1 } else { 0 })) `
                -Confirm:$false -ErrorAction Stop | Out-Null

            if ($null -ne $channel.MinimumSizeMB) {
                [long]$maxBytes = [long]$channel.MinimumSizeMB * 1MB
                Set-GPRegistryValue -Guid $gpoId -Domain $domainName -Server $pdcName `
                    -Key $channelKey -ValueName 'MaxSize' -Type QWord `
                    -Value $maxBytes -Confirm:$false -ErrorAction Stop | Out-Null
            }
            Write-Host ('{0,-45} : WRITTEN' -f $channel.Name)
        }
    }

    Write-Section 'VERIFY GPO CONTENT'
    $verified = Get-GPO -Guid $gpoId -Domain $domainName -Server $pdcName -ErrorAction Stop
    if (-not (Test-Path -LiteralPath $securityFile)) { throw 'Verification failed: GptTmpl.inf not found.' }
    if (-not (Test-Path -LiteralPath $auditFile)) { throw 'Verification failed: audit.csv not found.' }

    $writtenAuditRows = @(Import-Csv -LiteralPath $auditFile)
    if ($writtenAuditRows.Count -ne $auditRows.Count) {
        throw "Verification failed: audit.csv contains $($writtenAuditRows.Count) rows, expected $($auditRows.Count)."
    }

    $reportXmlPath = Join-Path $env:TEMP ('WSF-GPO-Report-' + $gpoId.ToString() + '.xml')
    Get-GPOReport -Guid $gpoId -Domain $domainName -Server $pdcName -ReportType Xml -Path $reportXmlPath -ErrorAction Stop

    # Import-Csv only verifies generic CSV structure. GPMC uses the stricter
    # MS-GPAC parser. Treat any audit.csv parsing error in Get-GPOReport as a
    # hard failure so a malformed Advanced Audit Policy can never be reported as
    # successfully configured.
    [xml]$verifiedReportXml = Get-Content -LiteralPath $reportXmlPath -Raw
    $reportErrors = @($verifiedReportXml.SelectNodes("//*[local-name()='Error']"))
    $auditReportErrors = @($reportErrors | Where-Object {
        $_.InnerText -match '(?i)audit\.csv|Advanced Audit|Auditing|CorruptAuditFile'
    })
    if ($auditReportErrors.Count -gt 0) {
        $auditErrorText = (($auditReportErrors | ForEach-Object { $_.InnerText.Trim() }) -join ' | ')
        throw "Verification failed: GPMC rejected Advanced Audit Policy audit.csv. Details: $auditErrorText"
    }

    Write-Host ('GPO verification           : PASS')
    Write-Host ('Security template          : PASS')
    Write-Host ('Advanced audit rows        : PASS ({0})' -f $writtenAuditRows.Count)
    Write-Host ('GPMC audit parser          : PASS')
    Write-Host ('GPO report                 : {0}' -f $reportXmlPath)
    Write-Host ('Computer version           : {0}' -f $verified.Computer.DSVersion)

    Write-Section 'RESULT'
    Write-Host 'Security Options          : WRITTEN'
    Write-Host 'Advanced Audit Policy     : WRITTEN (21)'
    Write-Host 'SpecialGroups             : WRITTEN'
    Write-Host 'Event Channels            : WRITTEN / ASSERTED'
    Write-Host 'GPO link operation        : NOT PERFORMED'
    Write-Host 'gpupdate                  : NOT PERFORMED'
    Write-Host ('Backup                    : {0}' -f $backupRoot)
    Write-Host ''
    Write-Host 'RESULT: WSF audit GPO configuration completed and GPMC structural verification passed.'
    Write-Host 'NEXT: Inspect Get-GPOReport and effective policy before any forced Group Policy refresh.'

    exit 0
}
catch {
    Write-Host ''
    Write-Host 'RESULT: FAIL'
    Write-Host ('ERROR : {0}' -f $_.Exception.Message)
    Write-Host 'NOTE  : If a real write had already started, use the printed Backup-GPO path before attempting rollback.'
    exit 1
}
finally {
    if ($null -ne (Get-Variable -Name nativeDc -ErrorAction SilentlyContinue) -and $null -ne $nativeDc) {
        try { $nativeDc.Dispose() } catch { }
    }
    if ($null -ne (Get-Variable -Name nativeDomain -ErrorAction SilentlyContinue) -and $null -ne $nativeDomain) {
        try { $nativeDomain.Dispose() } catch { }
    }
}
