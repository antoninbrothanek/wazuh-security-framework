#requires -Version 5.1

<#
.SYNOPSIS
    Creates the empty, unlinked Group Policy Object defined by a Wazuh Security
    Framework Windows audit policy.

.DESCRIPTION
    This script implements the deliberately narrow write stage that follows the
    read-only WSF audit policy planner. It validates the deployment safety flags
    in the XML policy, discovers the current Active Directory domain, confirms
    that the target GPO does not already exist, and can create that GPO.

    This version DOES NOT configure audit policy settings, security options,
    registry preferences, event channels, or GPO links. The only permitted
    production change is creation of a new, empty, unlinked GPO.

    Use -WhatIf first. Without -WhatIf, PowerShell ShouldProcess confirmation is
    required before New-GPO is invoked.

.PARAMETER PolicyFile
    Path to a WSF Windows audit policy XML file. Relative paths are resolved
    relative to this script so execution does not depend on the current working
    directory.

.PARAMETER GpoName
    Optional override for the GPO name defined in Metadata/Name.

.EXAMPLE
    .\create_wazuh_audit_gpo.ps1 `
        -PolicyFile ..\..\policies\windows\domain-controller-audit.xml `
        -WhatIf

.EXAMPLE
    .\create_wazuh_audit_gpo.ps1 `
        -PolicyFile ..\..\policies\windows\domain-controller-audit.xml

.NOTES
    Wazuh Security Framework
    Phase: Windows telemetry provisioning / unlinked GPO creation
    Safety boundary: creates an empty GPO only; never links it.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$PolicyFile,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$GpoName
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
        [Parameter(Mandatory = $true)][object]$Value,
        [Parameter(Mandatory = $true)][string]$Context
    )

    $text = [string]$Value
    switch ($text.ToLowerInvariant()) {
        'true'  { return $true }
        'false' { return $false }
        default { throw "Invalid Boolean value '$text' in $Context. Expected true or false." }
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

function Resolve-PolicyPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return (Resolve-Path -LiteralPath $Path).Path
    }

    $scriptRelativePath = Join-Path -Path $PSScriptRoot -ChildPath $Path
    return (Resolve-Path -LiteralPath $scriptRelativePath).Path
}

try {
    Write-Section 'WSF UNLINKED GPO CREATION'

    $resolvedPolicyFile = Resolve-PolicyPath -Path $PolicyFile
    Write-Host ('Policy file : {0}' -f $resolvedPolicyFile)

    [xml]$policy = Get-Content -LiteralPath $resolvedPolicyFile -Raw

    $root = $policy.SelectSingleNode('/WazuhSecurityFrameworkPolicy')
    if ($null -eq $root) {
        throw 'Root element WazuhSecurityFrameworkPolicy was not found.'
    }

    $schemaVersion = Get-RequiredAttribute -Node $root -Name 'schemaVersion' -Context 'WazuhSecurityFrameworkPolicy'
    $role = Get-RequiredAttribute -Node $root -Name 'role' -Context 'WazuhSecurityFrameworkPolicy'

    if ($schemaVersion -ne '1.0') {
        throw "Unsupported schemaVersion '$schemaVersion'."
    }

    if ($role -ne 'DomainController') {
        throw "Unsupported role '$role'."
    }

    $metadata = Get-RequiredXmlNode -Parent $root -XPath 'Metadata' -Context 'Metadata'
    $nameNode = Get-RequiredXmlNode -Parent $metadata -XPath 'Name' -Context 'Metadata/Name'
    $autoLinkNode = Get-RequiredXmlNode -Parent $metadata -XPath 'AutoLink' -Context 'Metadata/AutoLink'

    if ([string]::IsNullOrWhiteSpace($nameNode.InnerText)) {
        throw 'Metadata/Name cannot be empty.'
    }

    $effectiveGpoName = $nameNode.InnerText
    if (-not [string]::IsNullOrWhiteSpace($GpoName)) {
        $effectiveGpoName = $GpoName
    }

    $autoLink = ConvertTo-Bool -Value $autoLinkNode.InnerText -Context 'Metadata/AutoLink'

    $deployment = Get-RequiredXmlNode -Parent $root -XPath 'Deployment' -Context 'Deployment'
    $createGpo = ConvertTo-Bool -Value (Get-RequiredXmlNode -Parent $deployment -XPath 'CreateGpo' -Context 'Deployment/CreateGpo').InnerText -Context 'Deployment/CreateGpo'
    $linkGpo = ConvertTo-Bool -Value (Get-RequiredXmlNode -Parent $deployment -XPath 'LinkGpo' -Context 'Deployment/LinkGpo').InnerText -Context 'Deployment/LinkGpo'
    $requireExplicitLinkTarget = ConvertTo-Bool -Value (Get-RequiredXmlNode -Parent $deployment -XPath 'RequireExplicitLinkTarget' -Context 'Deployment/RequireExplicitLinkTarget').InnerText -Context 'Deployment/RequireExplicitLinkTarget'

    if (-not $createGpo) {
        throw 'Deployment/CreateGpo must be true before this script may create a GPO.'
    }

    if ($autoLink -or $linkGpo) {
        throw 'Safety check failed: automatic GPO linking must be disabled in the WSF policy.'
    }

    if (-not $requireExplicitLinkTarget) {
        throw 'Safety check failed: Deployment/RequireExplicitLinkTarget must be true.'
    }

    Write-Host ('Schema      : {0}' -f $schemaVersion)
    Write-Host ('Role        : {0}' -f $role)
    Write-Host ('GPO name    : {0}' -f $effectiveGpoName)
    Write-Host 'Auto-link   : disabled'

    Write-Section 'MODULES AND ACTIVE DIRECTORY'

    try {
        Import-Module ActiveDirectory -ErrorAction Stop
    }
    catch {
        throw "ActiveDirectory PowerShell module could not be loaded. Details: $($_.Exception.Message)"
    }

    try {
        Import-Module GroupPolicy -ErrorAction Stop
    }
    catch {
        throw "GroupPolicy PowerShell module could not be loaded. Details: $($_.Exception.Message)"
    }

    $domain = Get-ADDomain -ErrorAction Stop
    $domainName = [string]$domain.DNSRoot

    Write-Host ('Domain      : {0}' -f $domainName)

    Write-Section 'GPO DISCOVERY'

    # Get-GPO -All is intentional here. It distinguishes a truly absent GPO from
    # module, connectivity, permission, or provider errors that must stop writes.
    $matchingGpos = @(
        Get-GPO -All -Domain $domainName -ErrorAction Stop |
            Where-Object { [string]$_.DisplayName -eq $effectiveGpoName }
    )

    if ($matchingGpos.Count -gt 1) {
        throw "More than one GPO named '$effectiveGpoName' was returned. Refusing to continue."
    }

    if ($matchingGpos.Count -eq 1) {
        $existingGpo = $matchingGpos[0]
        Write-Host 'Existing GPO found : YES'
        Write-Host ('Display name        : {0}' -f $existingGpo.DisplayName)
        Write-Host ('GPO ID              : {0}' -f $existingGpo.Id)
        Write-Host ('GPO status          : {0}' -f $existingGpo.GpoStatus)
        Write-Host 'Action               : NONE'

        Write-Section 'RESULT'
        Write-Host 'GPO creation              : SKIPPED (already exists)'
        Write-Host 'GPO configuration         : NOT PERFORMED'
        Write-Host 'GPO link operation        : NOT PERFORMED'
        Write-Host 'Production changes        : NONE'
        Write-Host ''
        Write-Host 'RESULT: Existing GPO detected; no changes were made.'
        exit 0
    }

    Write-Host 'Existing GPO found : NO'
    Write-Host ('Planned GPO        : {0}' -f $effectiveGpoName)
    Write-Host ('Target domain      : {0}' -f $domainName)
    Write-Host 'Planned settings   : NONE (empty GPO in this phase)'
    Write-Host 'Planned link       : NONE'

    Write-Section 'WRITE SAFETY'
    Write-Host 'Allowed write              : New-GPO only'
    Write-Host 'Audit settings             : NOT WRITTEN'
    Write-Host 'Security options           : NOT WRITTEN'
    Write-Host 'Registry preferences       : NOT WRITTEN'
    Write-Host 'Event channel settings     : NOT WRITTEN'
    Write-Host 'New-GPLink                 : NOT USED'

    $targetDescription = "GPO '$effectiveGpoName' in domain '$domainName'"

    if (-not $PSCmdlet.ShouldProcess($targetDescription, 'Create empty, unlinked WSF GPO')) {
        Write-Section 'RESULT'
        Write-Host 'GPO creation              : NOT PERFORMED'
        Write-Host 'GPO configuration         : NOT PERFORMED'
        Write-Host 'GPO link operation        : NOT PERFORMED'
        Write-Host 'Production changes        : NONE'
        Write-Host ''
        if ($WhatIfPreference) {
            Write-Host 'RESULT: WHATIF validation passed. No GPO was created.'
        }
        else {
            Write-Host 'RESULT: GPO creation was not approved. No changes were made.'
        }
        exit 0
    }

    Write-Section 'CREATE GPO'

    $comment = 'Created by Wazuh Security Framework. Initial creation-only stage; GPO intentionally unlinked and not yet configured.'
    $createdGpo = New-GPO -Name $effectiveGpoName -Domain $domainName -Comment $comment -ErrorAction Stop

    # Verify through an independent read after creation.
    $verifiedGpo = Get-GPO -Name $effectiveGpoName -Domain $domainName -ErrorAction Stop

    if ([string]$verifiedGpo.Id -ne [string]$createdGpo.Id) {
        throw "GPO verification failed: created ID '$($createdGpo.Id)' does not match discovered ID '$($verifiedGpo.Id)'."
    }

    Write-Host ('Created GPO : {0}' -f $verifiedGpo.DisplayName)
    Write-Host ('GPO ID      : {0}' -f $verifiedGpo.Id)
    Write-Host ('GPO status  : {0}' -f $verifiedGpo.GpoStatus)

    Write-Section 'RESULT'
    Write-Host 'GPO creation              : PASS'
    Write-Host 'GPO verification          : PASS'
    Write-Host 'GPO configuration         : NOT PERFORMED'
    Write-Host 'GPO link operation        : NOT PERFORMED'
    Write-Host 'Automatic GPO linking     : DISABLED'
    Write-Host 'Production changes        : NEW EMPTY UNLINKED GPO ONLY'
    Write-Host ''
    Write-Host 'RESULT: Empty WSF GPO was created successfully and intentionally left unlinked.'
    Write-Host 'NEXT: Export/inspect the GPO before any policy settings are written.'

    exit 0
}
catch {
    Write-Host ''
    Write-Host 'RESULT: FAIL'
    Write-Host ('ERROR : {0}' -f $_.Exception.Message)
    exit 1
}
