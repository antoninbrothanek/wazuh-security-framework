#requires -Version 5.1

<#
.SYNOPSIS
    Validates a Wazuh Security Framework Windows audit policy definition and
    prepares a portable Group Policy deployment plan.

.DESCRIPTION
    This script is the first, deliberately safe stage of WSF Windows telemetry
    provisioning. It reads a WSF XML policy definition, validates the supported
    schema, resolves domain-specific SIDs at runtime, and prints the exact GPO
    configuration plan.

    The current implementation does NOT create, modify, link, or delete Group
    Policy Objects. This is intentional. Native GPO writers for Advanced Audit
    Policy and Security Options must be implemented and validated separately
    before write mode is enabled.

    Use -WhatIf during pilot validation. Because no write operations are
    implemented yet, normal execution is also read-only.

.PARAMETER PolicyFile
    Path to a WSF Windows audit policy XML file.

.PARAMETER GpoName
    Optional override for the GPO name defined in the XML metadata.

.PARAMETER SkipActiveDirectoryResolution
    Validate the XML without resolving DomainRid and ForestRootDomainRid values.
    Intended for offline linting only. Portable SID placeholders will remain
    unresolved in the resulting plan.

.EXAMPLE
    .\create_wazuh_audit.ps1 `
        -PolicyFile ..\..\policies\windows\domain-controller-audit.xml `
        -WhatIf

.EXAMPLE
    .\create_wazuh_audit.ps1 `
        -PolicyFile ..\..\policies\windows\domain-controller-audit.xml `
        -SkipActiveDirectoryResolution

.NOTES
    Wazuh Security Framework
    Phase: Windows telemetry provisioning / planner
    Safety: read-only; no GPO writes are performed by this version.
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
    [switch]$SkipActiveDirectoryResolution
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Write-Section {
    param([Parameter(Mandatory = $true)][string]$Title)

    Write-Host ''
    Write-Host ('===== {0} =====' -f $Title)
}

function ConvertTo-Bool {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Value,

        [Parameter(Mandatory = $true)]
        [string]$Context
    )

    $text = [string]$Value

    switch ($text.ToLowerInvariant()) {
        'true'  { return $true }
        'false' { return $false }
        default { throw "Invalid Boolean value '$text' in $Context. Expected true or false." }
    }
}

function Assert-AllowedValue {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][string[]]$Allowed,
        [Parameter(Mandatory = $true)][string]$Context
    )

    if ($Allowed -notcontains $Value) {
        throw "Unsupported value '$Value' in $Context. Allowed values: $($Allowed -join ', ')."
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

function Resolve-WsfSpecialGroupSid {
    param(
        [Parameter(Mandatory = $true)][System.Xml.XmlNode]$Group,
        [Parameter(Mandatory = $false)][string]$DomainSid,
        [Parameter(Mandatory = $false)][string]$ForestRootDomainSid,
        [Parameter(Mandatory = $true)][bool]$ResolveActiveDirectory
    )

    $type = Get-RequiredAttribute -Node $Group -Name 'type' -Context 'SpecialGroups/Group'
    $name = Get-RequiredAttribute -Node $Group -Name 'name' -Context 'SpecialGroups/Group'

    switch ($type) {
        'WellKnownSid' {
            $sid = Get-RequiredAttribute -Node $Group -Name 'sid' -Context "SpecialGroups/Group '$name'"
            if ($sid -notmatch '^S-1-[0-9-]+$') {
                throw "Invalid SID '$sid' for SpecialGroups/Group '$name'."
            }
            return $sid
        }

        'DomainRid' {
            $rid = Get-RequiredAttribute -Node $Group -Name 'rid' -Context "SpecialGroups/Group '$name'"
            if ($rid -notmatch '^\d+$') {
                throw "Invalid RID '$rid' for SpecialGroups/Group '$name'."
            }

            if (-not $ResolveActiveDirectory) {
                return ('<DOMAIN-SID>-{0}' -f $rid)
            }

            if ([string]::IsNullOrWhiteSpace($DomainSid)) {
                throw "Domain SID is unavailable while resolving '$name'."
            }

            return ('{0}-{1}' -f $DomainSid, $rid)
        }

        'ForestRootDomainRid' {
            $rid = Get-RequiredAttribute -Node $Group -Name 'rid' -Context "SpecialGroups/Group '$name'"
            if ($rid -notmatch '^\d+$') {
                throw "Invalid RID '$rid' for SpecialGroups/Group '$name'."
            }

            if (-not $ResolveActiveDirectory) {
                return ('<FOREST-ROOT-DOMAIN-SID>-{0}' -f $rid)
            }

            if ([string]::IsNullOrWhiteSpace($ForestRootDomainSid)) {
                throw "Forest root domain SID is unavailable while resolving '$name'."
            }

            return ('{0}-{1}' -f $ForestRootDomainSid, $rid)
        }

        default {
            throw "Unsupported SpecialGroups type '$type' for '$name'."
        }
    }
}

function Get-AuditSettingText {
    param(
        [Parameter(Mandatory = $true)][bool]$Success,
        [Parameter(Mandatory = $true)][bool]$Failure
    )

    if ($Success -and $Failure) { return 'Success, Failure' }
    if ($Success) { return 'Success' }
    if ($Failure) { return 'Failure' }
    return 'No Auditing'
}

try {
    Write-Section 'WSF WINDOWS AUDIT POLICY'

    $resolvedPolicyFile = (Resolve-Path -LiteralPath $PolicyFile).Path
    Write-Host ('Policy file : {0}' -f $resolvedPolicyFile)

    $rawXml = Get-Content -LiteralPath $resolvedPolicyFile -Raw
    [xml]$policy = $rawXml

    $root = $policy.SelectSingleNode('/WazuhSecurityFrameworkPolicy')
    if ($null -eq $root) {
        throw 'Root element WazuhSecurityFrameworkPolicy was not found.'
    }

    $schemaVersion = Get-RequiredAttribute -Node $root -Name 'schemaVersion' -Context 'WazuhSecurityFrameworkPolicy'
    $policyVersion = Get-RequiredAttribute -Node $root -Name 'policyVersion' -Context 'WazuhSecurityFrameworkPolicy'
    $role = Get-RequiredAttribute -Node $root -Name 'role' -Context 'WazuhSecurityFrameworkPolicy'

    Assert-AllowedValue -Value $schemaVersion -Allowed @('1.0') -Context 'schemaVersion'
    Assert-AllowedValue -Value $role -Allowed @('DomainController') -Context 'role'

    $metadata = Get-RequiredXmlNode -Parent $root -XPath 'Metadata' -Context 'Metadata'
    $metadataNameNode = Get-RequiredXmlNode -Parent $metadata -XPath 'Name' -Context 'Metadata/Name'
    $metadataScopeNode = Get-RequiredXmlNode -Parent $metadata -XPath 'Scope' -Context 'Metadata/Scope'
    $metadataAutoLinkNode = Get-RequiredXmlNode -Parent $metadata -XPath 'AutoLink' -Context 'Metadata/AutoLink'

    if ([string]::IsNullOrWhiteSpace($metadataNameNode.InnerText)) {
        throw 'Metadata/Name cannot be empty.'
    }

    Assert-AllowedValue -Value $metadataScopeNode.InnerText -Allowed @('Computer') -Context 'Metadata/Scope'
    $autoLink = ConvertTo-Bool -Value $metadataAutoLinkNode.InnerText -Context 'Metadata/AutoLink'

    $effectiveGpoName = $metadataNameNode.InnerText
    if (-not [string]::IsNullOrWhiteSpace($GpoName)) {
        $effectiveGpoName = $GpoName
    }

    $deployment = Get-RequiredXmlNode -Parent $root -XPath 'Deployment' -Context 'Deployment'
    $createGpo = ConvertTo-Bool -Value (Get-RequiredXmlNode -Parent $deployment -XPath 'CreateGpo' -Context 'Deployment/CreateGpo').InnerText -Context 'Deployment/CreateGpo'
    $linkGpo = ConvertTo-Bool -Value (Get-RequiredXmlNode -Parent $deployment -XPath 'LinkGpo' -Context 'Deployment/LinkGpo').InnerText -Context 'Deployment/LinkGpo'
    $requireExplicitLinkTarget = ConvertTo-Bool -Value (Get-RequiredXmlNode -Parent $deployment -XPath 'RequireExplicitLinkTarget' -Context 'Deployment/RequireExplicitLinkTarget').InnerText -Context 'Deployment/RequireExplicitLinkTarget'

    if ($autoLink -or $linkGpo) {
        throw 'Automatic GPO linking is not permitted by this implementation. Set Metadata/AutoLink and Deployment/LinkGpo to false.'
    }

    if (-not $requireExplicitLinkTarget) {
        throw 'Deployment/RequireExplicitLinkTarget must be true for WSF portable policies.'
    }

    Write-Host ('Schema      : {0}' -f $schemaVersion)
    Write-Host ('Policy      : {0}' -f $policyVersion)
    Write-Host ('Role        : {0}' -f $role)
    Write-Host ('GPO name    : {0}' -f $effectiveGpoName)
    Write-Host ('Create GPO  : {0}' -f $createGpo)
    Write-Host ('Auto-link   : disabled')

    # Validate Security Options.
    $securityOptions = Get-RequiredXmlNode -Parent $root -XPath 'SecurityOptions' -Context 'SecurityOptions'
    $forceAdvancedAudit = Get-RequiredXmlNode -Parent $securityOptions -XPath 'ForceAdvancedAuditPolicy' -Context 'SecurityOptions/ForceAdvancedAuditPolicy'
    $forceAdvancedAuditEnabled = ConvertTo-Bool -Value (Get-RequiredAttribute -Node $forceAdvancedAudit -Name 'enabled' -Context 'SecurityOptions/ForceAdvancedAuditPolicy') -Context 'SecurityOptions/ForceAdvancedAuditPolicy@enabled'

    $ntlm = Get-RequiredXmlNode -Parent $securityOptions -XPath 'NTLMAuditing' -Context 'SecurityOptions/NTLMAuditing'
    $incomingMode = Get-RequiredAttribute -Node (Get-RequiredXmlNode -Parent $ntlm -XPath 'Incoming' -Context 'NTLMAuditing/Incoming') -Name 'mode' -Context 'NTLMAuditing/Incoming'
    $domainMode = Get-RequiredAttribute -Node (Get-RequiredXmlNode -Parent $ntlm -XPath 'DomainAuthentication' -Context 'NTLMAuditing/DomainAuthentication') -Name 'mode' -Context 'NTLMAuditing/DomainAuthentication'
    $outgoingMode = Get-RequiredAttribute -Node (Get-RequiredXmlNode -Parent $ntlm -XPath 'Outgoing' -Context 'NTLMAuditing/Outgoing') -Name 'mode' -Context 'NTLMAuditing/Outgoing'

    Assert-AllowedValue -Value $incomingMode -Allowed @('AuditAllAccounts') -Context 'NTLMAuditing/Incoming@mode'
    Assert-AllowedValue -Value $domainMode -Allowed @('AuditAll') -Context 'NTLMAuditing/DomainAuthentication@mode'
    Assert-AllowedValue -Value $outgoingMode -Allowed @('AuditAll') -Context 'NTLMAuditing/Outgoing@mode'

    # Validate Advanced Audit Policy.
    $advancedAudit = Get-RequiredXmlNode -Parent $root -XPath 'AdvancedAuditPolicy' -Context 'AdvancedAuditPolicy'
    $auditRows = @()

    foreach ($category in $advancedAudit.SelectNodes('Category')) {
        $categoryName = Get-RequiredAttribute -Node $category -Name 'name' -Context 'AdvancedAuditPolicy/Category'
        $subcategories = $category.SelectNodes('Subcategory')

        if ($subcategories.Count -eq 0) {
            throw "Advanced Audit Policy category '$categoryName' contains no Subcategory elements."
        }

        foreach ($subcategory in $subcategories) {
            $subcategoryName = Get-RequiredAttribute -Node $subcategory -Name 'name' -Context "AdvancedAuditPolicy/Category '$categoryName'/Subcategory"
            $success = ConvertTo-Bool -Value (Get-RequiredAttribute -Node $subcategory -Name 'success' -Context "Subcategory '$subcategoryName'") -Context "Subcategory '$subcategoryName'@success"
            $failure = ConvertTo-Bool -Value (Get-RequiredAttribute -Node $subcategory -Name 'failure' -Context "Subcategory '$subcategoryName'") -Context "Subcategory '$subcategoryName'@failure"

            $auditRows += [pscustomobject]@{
                Category = $categoryName
                Subcategory = $subcategoryName
                Setting = Get-AuditSettingText -Success $success -Failure $failure
            }
        }
    }

    if ($auditRows.Count -eq 0) {
        throw 'AdvancedAuditPolicy contains no audit settings.'
    }

    # Resolve Active Directory context only when requested.
    $resolveActiveDirectory = -not $SkipActiveDirectoryResolution.IsPresent
    $domainName = $null
    $domainSid = $null
    $forestName = $null
    $forestRootDomain = $null
    $forestRootDomainSid = $null

    if ($resolveActiveDirectory) {
        Write-Section 'ACTIVE DIRECTORY CONTEXT'

        if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
            throw 'ActiveDirectory PowerShell module is required for SID resolution. Install RSAT AD PowerShell or use -SkipActiveDirectoryResolution for offline validation.'
        }

        Import-Module ActiveDirectory -ErrorAction Stop

        $domain = Get-ADDomain -ErrorAction Stop
        $forest = Get-ADForest -ErrorAction Stop
        $rootDomain = Get-ADDomain -Identity $forest.RootDomain -ErrorAction Stop

        $domainName = $domain.DNSRoot
        $domainSid = $domain.DomainSID.Value
        $forestName = $forest.Name
        $forestRootDomain = $forest.RootDomain
        $forestRootDomainSid = $rootDomain.DomainSID.Value

        Write-Host ('Domain              : {0}' -f $domainName)
        Write-Host ('Domain SID          : {0}' -f $domainSid)
        Write-Host ('Forest              : {0}' -f $forestName)
        Write-Host ('Forest root domain  : {0}' -f $forestRootDomain)
        Write-Host ('Forest root SID     : {0}' -f $forestRootDomainSid)
    }
    else {
        Write-Section 'ACTIVE DIRECTORY CONTEXT'
        Write-Host 'SID resolution skipped (offline validation mode).'
    }

    # Validate and resolve SpecialGroups.
    $specialGroupsNode = Get-RequiredXmlNode -Parent $root -XPath 'SpecialGroups' -Context 'SpecialGroups'
    $specialGroupRows = @()

    foreach ($group in $specialGroupsNode.SelectNodes('Group')) {
        $groupName = Get-RequiredAttribute -Node $group -Name 'name' -Context 'SpecialGroups/Group'
        $groupType = Get-RequiredAttribute -Node $group -Name 'type' -Context "SpecialGroups/Group '$groupName'"
        $resolvedSid = Resolve-WsfSpecialGroupSid -Group $group -DomainSid $domainSid -ForestRootDomainSid $forestRootDomainSid -ResolveActiveDirectory $resolveActiveDirectory

        $specialGroupRows += [pscustomobject]@{
            Name = $groupName
            Type = $groupType
            SID = $resolvedSid
        }
    }

    if ($specialGroupRows.Count -eq 0) {
        throw 'SpecialGroups contains no Group elements.'
    }

    $specialGroupsRegistryValue = ($specialGroupRows.SID -join ';')

    # Validate Event Channels.
    $eventChannelsNode = Get-RequiredXmlNode -Parent $root -XPath 'EventChannels' -Context 'EventChannels'
    $eventChannelRows = @()

    foreach ($channel in $eventChannelsNode.SelectNodes('Channel')) {
        $channelName = Get-RequiredAttribute -Node $channel -Name 'name' -Context 'EventChannels/Channel'
        $enabled = ConvertTo-Bool -Value (Get-RequiredAttribute -Node $channel -Name 'enabled' -Context "EventChannels/Channel '$channelName'") -Context "EventChannels/Channel '$channelName'@enabled"

        $minimumSizeMB = $null
        if ($null -ne $channel.Attributes['minimumSizeMB']) {
            $minimumSizeText = $channel.Attributes['minimumSizeMB'].Value
            [int]$parsedMinimumSize = 0
            if (-not [int]::TryParse($minimumSizeText, [ref]$parsedMinimumSize) -or $parsedMinimumSize -le 0) {
                throw "Invalid minimumSizeMB '$minimumSizeText' for event channel '$channelName'."
            }
            $minimumSizeMB = $parsedMinimumSize
        }

        $eventChannelRows += [pscustomobject]@{
            Channel = $channelName
            Enabled = $enabled
            MinimumSizeMB = $minimumSizeMB
        }
    }

    if ($eventChannelRows.Count -eq 0) {
        throw 'EventChannels contains no Channel elements.'
    }

    # Optional read-only GPO discovery. The planner must never require GroupPolicy
    # merely to lint an XML file offline.
    $existingGpo = $null
    if (Get-Module -ListAvailable -Name GroupPolicy) {
        Import-Module GroupPolicy -ErrorAction Stop
        try {
            $existingGpo = Get-GPO -Name $effectiveGpoName -ErrorAction Stop
        }
        catch {
            $existingGpo = $null
        }
    }

    Write-Section 'SECURITY OPTIONS PLAN'
    Write-Host ('Force advanced audit policy override : {0}' -f $(if ($forceAdvancedAuditEnabled) { 'Enabled' } else { 'Disabled' }))
    Write-Host ('NTLM incoming auditing               : {0}' -f $incomingMode)
    Write-Host ('NTLM domain authentication auditing  : {0}' -f $domainMode)
    Write-Host ('NTLM outgoing auditing               : {0}' -f $outgoingMode)

    Write-Section 'ADVANCED AUDIT POLICY PLAN'
    foreach ($row in $auditRows) {
        Write-Host ('{0,-22} | {1,-42} | {2}' -f $row.Category, $row.Subcategory, $row.Setting)
    }

    Write-Section 'SPECIAL GROUPS PLAN'
    foreach ($row in $specialGroupRows) {
        Write-Host ('{0,-22} | {1,-20} | {2}' -f $row.Name, $row.Type, $row.SID)
    }
    Write-Host ''
    Write-Host ('Registry value: {0}' -f $specialGroupsRegistryValue)

    Write-Section 'EVENT CHANNEL PLAN'
    foreach ($row in $eventChannelRows) {
        $sizeText = '-'
        if ($null -ne $row.MinimumSizeMB) {
            $sizeText = ('{0} MB minimum' -f $row.MinimumSizeMB)
        }

        Write-Host ('{0,-45} | Enabled={1,-5} | {2}' -f $row.Channel, $row.Enabled, $sizeText)
    }

    Write-Section 'GPO DISCOVERY'
    if ($null -ne $existingGpo) {
        Write-Host ('Existing GPO found : YES')
        Write-Host ('Display name        : {0}' -f $existingGpo.DisplayName)
        Write-Host ('GPO ID              : {0}' -f $existingGpo.Id)
        Write-Host ('GPO status          : {0}' -f $existingGpo.GpoStatus)
        Write-Host 'Action               : NONE (read-only planner)'
    }
    else {
        Write-Host 'Existing GPO found : NO or GroupPolicy module unavailable'
        Write-Host ('Planned GPO        : {0}' -f $effectiveGpoName)
        Write-Host 'Action             : NONE (read-only planner)'
    }

    Write-Section 'VALIDATION RESULT'
    Write-Host 'XML policy                 : PASS'
    Write-Host ('Advanced audit settings    : PASS ({0})' -f $auditRows.Count)
    Write-Host ('Special groups             : PASS ({0})' -f $specialGroupRows.Count)
    Write-Host ('Event channels             : PASS ({0})' -f $eventChannelRows.Count)
    Write-Host ('SID resolution             : {0}' -f $(if ($resolveActiveDirectory) { 'PASS' } else { 'SKIPPED' }))
    Write-Host 'Automatic GPO linking       : DISABLED'
    Write-Host 'Production changes          : NONE'

    if ($WhatIfPreference) {
        Write-Host 'Execution mode              : WHATIF / READ-ONLY'
    }
    else {
        Write-Host 'Execution mode              : READ-ONLY'
    }

    Write-Host ''
    Write-Host 'RESULT: WSF audit policy definition is valid for provisioning-plan testing.'
    Write-Host 'NOTE: GPO write support is intentionally not enabled in this version.'

    exit 0
}
catch {
    Write-Host ''
    Write-Host 'RESULT: FAIL'
    Write-Host ('ERROR : {0}' -f $_.Exception.Message)
    exit 1
}
