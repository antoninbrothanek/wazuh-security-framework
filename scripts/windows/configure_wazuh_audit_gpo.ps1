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
      - Event channels: prerequisite declarations only; no WINEVT registry writes

    The script performs all validation before writing, creates a GPO backup,
    writes through one domain controller, and registers the Security and
    Advanced Audit Policy client-side extensions so the GPO revision is updated.

    IMPORTANT: early WSF builds wrote Enabled/MaxSize directly below the WINEVT
    channel-registration registry path. Pilot validation showed that this can
    break the Event Log configuration API. This writer removes those legacy GPO
    values when present and never creates them again.

    PowerShell 7 is supported as a launcher. The script relaunches itself in
    Windows PowerShell 5.1 because the Microsoft Group Policy management API is
    a Windows PowerShell / GPMC component.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$PolicyFile,
    [Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()][string]$GpoName,
    [Parameter(Mandatory = $false)][switch]$AllowLinkedGpo
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Write-Section { param([Parameter(Mandatory=$true)][string]$Title); Write-Host ''; Write-Host ('===== {0} =====' -f $Title) }
function Resolve-PolicyPath { param([Parameter(Mandatory=$true)][string]$Path); if ([IO.Path]::IsPathRooted($Path)) { return (Resolve-Path -LiteralPath $Path).Path }; return (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot $Path)).Path }
function ConvertTo-Bool { param([Parameter(Mandatory=$true)][object]$Value,[Parameter(Mandatory=$true)][string]$Context); switch (([string]$Value).ToLowerInvariant()) { 'true' { $true } 'false' { $false } default { throw "Invalid Boolean value '$Value' in $Context." } } }
function Get-RequiredXmlNode { param([Parameter(Mandatory=$true)][Xml.XmlNode]$Parent,[Parameter(Mandatory=$true)][string]$XPath,[Parameter(Mandatory=$true)][string]$Context); $n=$Parent.SelectSingleNode($XPath); if($null -eq $n){throw "Missing required XML element: $Context ($XPath)."}; $n }
function Get-RequiredAttribute { param([Parameter(Mandatory=$true)][Xml.XmlNode]$Node,[Parameter(Mandatory=$true)][string]$Name,[Parameter(Mandatory=$true)][string]$Context); if($null -eq $Node.Attributes[$Name] -or [string]::IsNullOrWhiteSpace($Node.Attributes[$Name].Value)){throw "Missing required attribute '$Name' in $Context."}; $Node.Attributes[$Name].Value }
function ConvertTo-SidString { param([Parameter(Mandatory=$true)][object]$Sid,[Parameter(Mandatory=$true)][string]$Context); if($null -eq $Sid){throw "SID is unavailable for $Context."}; $s=if($null -ne $Sid.PSObject.Properties['Value']){[string]$Sid.Value}else{[string]$Sid}; if($s -notmatch '^S-1-[0-9-]+$'){throw "Invalid SID '$s' returned for $Context."}; $s }
function Get-AuditSetting { param([bool]$Success,[bool]$Failure); if($Success -and $Failure){return [pscustomobject]@{Inclusion='Success and Failure';Value=3}}; if($Success){return [pscustomobject]@{Inclusion='Success';Value=1}}; if($Failure){return [pscustomobject]@{Inclusion='Failure';Value=2}}; [pscustomobject]@{Inclusion='No Auditing';Value=0} }
function Write-Utf8NoBom { param([string]$Path,[string]$Content); [IO.File]::WriteAllText($Path,$Content,(New-Object Text.UTF8Encoding($false))) }
function Register-GpoExtension { param([DirectoryServices.ActiveDirectory.DomainController]$DomainController,[guid]$GpoId,[guid]$ClientSideExtension,[guid]$Editor); $nativeGpo=New-Object Microsoft.GroupPolicy.GroupPolicyObject; try{$nativeGpo.OpenDSGpo($DomainController,$GpoId,$false,$false);$nativeGpo.Save($true,$true,$ClientSideExtension,$Editor)}finally{$nativeGpo.Dispose()} }

if ($PSVersionTable.PSEdition -eq 'Core') {
    $windowsPowerShell=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if(-not(Test-Path -LiteralPath $windowsPowerShell)){throw "Windows PowerShell 5.1 was not found at '$windowsPowerShell'."}
    $relaunchArgs=@('-NoProfile','-ExecutionPolicy','Bypass','-File',$PSCommandPath,'-PolicyFile',$PolicyFile)
    if(-not[string]::IsNullOrWhiteSpace($GpoName)){$relaunchArgs+=@('-GpoName',$GpoName)}
    if($AllowLinkedGpo){$relaunchArgs+='-AllowLinkedGpo'}; if($WhatIfPreference){$relaunchArgs+='-WhatIf'}
    Write-Host 'WSF: Relaunching GPO configuration writer in Windows PowerShell 5.1...'; & $windowsPowerShell @relaunchArgs; exit $LASTEXITCODE
}

try {
    Write-Section 'WSF AUDIT GPO CONFIGURATION'
    $resolvedPolicyFile=Resolve-PolicyPath $PolicyFile; [xml]$policy=Get-Content -LiteralPath $resolvedPolicyFile -Raw
    $root=$policy.SelectSingleNode('/WazuhSecurityFrameworkPolicy'); if($null -eq $root){throw 'Root element WazuhSecurityFrameworkPolicy was not found.'}
    $schemaVersion=Get-RequiredAttribute $root 'schemaVersion' 'WazuhSecurityFrameworkPolicy'; $role=Get-RequiredAttribute $root 'role' 'WazuhSecurityFrameworkPolicy'
    if($schemaVersion -ne '1.0'){throw "Unsupported schemaVersion '$schemaVersion'."}; if($role -ne 'DomainController'){throw "Unsupported role '$role'."}
    $metadata=Get-RequiredXmlNode $root 'Metadata' 'Metadata'; $effectiveGpoName=(Get-RequiredXmlNode $metadata 'Name' 'Metadata/Name').InnerText; if(-not[string]::IsNullOrWhiteSpace($GpoName)){$effectiveGpoName=$GpoName}
    $autoLink=ConvertTo-Bool (Get-RequiredXmlNode $metadata 'AutoLink' 'Metadata/AutoLink').InnerText 'Metadata/AutoLink'
    $deployment=Get-RequiredXmlNode $root 'Deployment' 'Deployment'; $linkGpo=ConvertTo-Bool (Get-RequiredXmlNode $deployment 'LinkGpo' 'Deployment/LinkGpo').InnerText 'Deployment/LinkGpo'; $requireExplicit=ConvertTo-Bool (Get-RequiredXmlNode $deployment 'RequireExplicitLinkTarget' 'Deployment/RequireExplicitLinkTarget').InnerText 'Deployment/RequireExplicitLinkTarget'
    if($autoLink -or $linkGpo){throw 'Safety check failed: automatic GPO linking must remain disabled.'}; if(-not$requireExplicit){throw 'Safety check failed: RequireExplicitLinkTarget must be true.'}

    Import-Module ActiveDirectory -ErrorAction Stop; Import-Module GroupPolicy -ErrorAction Stop; Add-Type -AssemblyName Microsoft.GroupPolicy.Management.Interop -ErrorAction Stop
    $domain=Get-ADDomain; $forest=Get-ADForest; $rootDomain=Get-ADDomain -Identity $forest.RootDomain; $domainName=[string]$domain.DNSRoot; $pdcName=[string]$domain.PDCEmulator
    $domainSid=ConvertTo-SidString $domain.DomainSID 'current domain'; $forestRootSid=ConvertTo-SidString $rootDomain.DomainSID 'forest root domain'
    $nativeDomain=[DirectoryServices.ActiveDirectory.Domain]::GetDomain((New-Object DirectoryServices.ActiveDirectory.DirectoryContext('Domain',$domainName))); $dcContext=New-Object DirectoryServices.ActiveDirectory.DirectoryContext('DirectoryServer',$pdcName); $nativeDc=[DirectoryServices.ActiveDirectory.DomainController]::GetDomainController($dcContext)

    $gpo=Get-GPO -Name $effectiveGpoName -Domain $domainName -Server $pdcName -ErrorAction Stop; $gpoId=[guid]$gpo.Id; $gpoGuidBraced='{'+$gpoId.ToString().ToUpperInvariant()+'}'
    [xml]$gpoReport=Get-GPOReport -Guid $gpoId -Domain $domainName -Server $pdcName -ReportType Xml; $linkCount=@($gpoReport.SelectNodes("//*[local-name()='LinksTo']")).Count
    Write-Host ('GPO name       : {0}' -f $effectiveGpoName); Write-Host ('Existing links : {0}' -f $linkCount)
    if($linkCount -gt 0 -and -not$AllowLinkedGpo){throw "Target GPO already has $linkCount link(s). Refusing to configure it without explicit -AllowLinkedGpo acknowledgement."}

    $securityOptions=Get-RequiredXmlNode $root 'SecurityOptions' 'SecurityOptions'; $forceAdvancedNode=Get-RequiredXmlNode $securityOptions 'ForceAdvancedAuditPolicy' 'ForceAdvancedAuditPolicy'; $forceAdvanced=ConvertTo-Bool (Get-RequiredAttribute $forceAdvancedNode 'enabled' 'ForceAdvancedAuditPolicy') 'ForceAdvancedAuditPolicy@enabled'
    $ntlm=Get-RequiredXmlNode $securityOptions 'NTLMAuditing' 'NTLMAuditing'; $incomingMode=Get-RequiredAttribute (Get-RequiredXmlNode $ntlm 'Incoming' 'Incoming') 'mode' 'Incoming'; $domainMode=Get-RequiredAttribute (Get-RequiredXmlNode $ntlm 'DomainAuthentication' 'DomainAuthentication') 'mode' 'DomainAuthentication'; $outgoingMode=Get-RequiredAttribute (Get-RequiredXmlNode $ntlm 'Outgoing' 'Outgoing') 'mode' 'Outgoing'
    if($incomingMode -ne 'AuditAllAccounts' -or $domainMode -ne 'AuditAll' -or $outgoingMode -ne 'AuditAll'){throw 'Unsupported NTLM auditing mode.'}
    $securityRegistryValues=@([pscustomobject]@{Key='MACHINE\System\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy';Value=$(if($forceAdvanced){1}else{0})},[pscustomobject]@{Key='MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\AuditReceivingNTLMTraffic';Value=2},[pscustomobject]@{Key='MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\RestrictSendingNTLMTraffic';Value=1},[pscustomobject]@{Key='MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\AuditNTLMInDomain';Value=7})

    $auditGuidMap=@{'Credential Validation'='{0CCE923F-69AE-11D9-BED3-505054503030}';'Kerberos Authentication Service'='{0CCE9242-69AE-11D9-BED3-505054503030}';'Kerberos Service Ticket Operations'='{0CCE9240-69AE-11D9-BED3-505054503030}';'Other Account Logon Events'='{0CCE9241-69AE-11D9-BED3-505054503030}';'Application Group Management'='{0CCE9239-69AE-11D9-BED3-505054503030}';'Computer Account Management'='{0CCE9236-69AE-11D9-BED3-505054503030}';'Distribution Group Management'='{0CCE9238-69AE-11D9-BED3-505054503030}';'Other Account Management Events'='{0CCE923A-69AE-11D9-BED3-505054503030}';'Security Group Management'='{0CCE9237-69AE-11D9-BED3-505054503030}';'User Account Management'='{0CCE9235-69AE-11D9-BED3-505054503030}';'Process Creation'='{0CCE922B-69AE-11D9-BED3-505054503030}';'Directory Service Changes'='{0CCE923C-69AE-11D9-BED3-505054503030}';'Account Lockout'='{0CCE9217-69AE-11D9-BED3-505054503030}';'Logoff'='{0CCE9216-69AE-11D9-BED3-505054503030}';'Logon'='{0CCE9215-69AE-11D9-BED3-505054503030}';'Special Logon'='{0CCE921B-69AE-11D9-BED3-505054503030}';'Audit Policy Change'='{0CCE922F-69AE-11D9-BED3-505054503030}';'Authentication Policy Change'='{0CCE9230-69AE-11D9-BED3-505054503030}';'Authorization Policy Change'='{0CCE9231-69AE-11D9-BED3-505054503030}';'Sensitive Privilege Use'='{0CCE9228-69AE-11D9-BED3-505054503030}';'Security System Extension'='{0CCE9211-69AE-11D9-BED3-505054503030}'}
    $auditRows=@(); $advancedAudit=Get-RequiredXmlNode $root 'AdvancedAuditPolicy' 'AdvancedAuditPolicy'; foreach($category in $advancedAudit.SelectNodes('Category')){foreach($subcategory in $category.SelectNodes('Subcategory')){$name=Get-RequiredAttribute $subcategory 'name' 'Subcategory'; if(-not$auditGuidMap.ContainsKey($name)){throw "No approved Advanced Audit Policy GUID mapping exists for '$name'."}; $setting=Get-AuditSetting (ConvertTo-Bool (Get-RequiredAttribute $subcategory 'success' $name) "$name@success") (ConvertTo-Bool (Get-RequiredAttribute $subcategory 'failure' $name) "$name@failure"); $auditRows+=[pscustomobject]@{Name=$name;Guid=$auditGuidMap[$name];Inclusion=$setting.Inclusion;Value=$setting.Value}}}; if($auditRows.Count -ne 21){throw "Expected 21 Advanced Audit Policy rows; found $($auditRows.Count)."}

    $resolvedSids=@(); foreach($group in (Get-RequiredXmlNode $root 'SpecialGroups' 'SpecialGroups').SelectNodes('Group')){$type=Get-RequiredAttribute $group 'type' 'SpecialGroups/Group';$name=Get-RequiredAttribute $group 'name' 'SpecialGroups/Group';switch($type){'WellKnownSid'{$resolvedSids+=Get-RequiredAttribute $group 'sid' $name}'DomainRid'{$resolvedSids+="$domainSid-$(Get-RequiredAttribute $group 'rid' $name)"}'ForestRootDomainRid'{$resolvedSids+="$forestRootSid-$(Get-RequiredAttribute $group 'rid' $name)"}default{throw "Unsupported SpecialGroups type '$type'."}}}; $specialGroupsValue=$resolvedSids -join ';'

    $eventChannels=@(); foreach($channel in (Get-RequiredXmlNode $root 'EventChannels' 'EventChannels').SelectNodes('Channel')){$channelName=Get-RequiredAttribute $channel 'name' 'EventChannels/Channel';$enabled=ConvertTo-Bool (Get-RequiredAttribute $channel 'enabled' $channelName) "$channelName@enabled";if($null -ne $channel.Attributes['minimumSizeMB']){throw "Event channel '$channelName' contains deprecated minimumSizeMB. WSF event-channel declarations are validation-only."};if($channelName -notin @('Security','Microsoft-Windows-NTLM/Operational')){throw "Unsupported event channel '$channelName'."};if(-not$enabled){throw "WSF requires event channel '$channelName' to be enabled."};$eventChannels+=$channelName}

    Write-Section 'CONFIGURATION PLAN'; Write-Host ('Security options        : {0}' -f $securityRegistryValues.Count);Write-Host ('Advanced audit settings : {0}' -f $auditRows.Count);Write-Host ('Special groups          : {0}' -f $resolvedSids.Count);Write-Host ('Event channels          : {0} prerequisite assertions; NO registry writes' -f $eventChannels.Count);Write-Host 'GPO link operations     : NONE';Write-Host 'gpupdate                : NOT USED'

    $securityLines=@('[Unicode]','Unicode=yes','[Version]','signature="$CHICAGO$"','Revision=1','[Registry Values]');foreach($entry in $securityRegistryValues){$securityLines+=('{0}=4,{1}' -f $entry.Key,$entry.Value)};$securityTemplate=($securityLines -join "`r`n")+"`r`n"
    $auditLines=@('Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value');foreach($row in $auditRows){$auditLines+=('WSF,System,{0},{1},{2},,{3}' -f $row.Name,$row.Guid,$row.Inclusion,$row.Value)};$auditCsv=($auditLines -join "`r`n")+"`r`n"
    $machineRoot="\\$pdcName\SYSVOL\$domainName\Policies\$gpoGuidBraced\Machine";$securityDir=Join-Path $machineRoot 'Microsoft\Windows NT\SecEdit';$securityFile=Join-Path $securityDir 'GptTmpl.inf';$auditDir=Join-Path $machineRoot 'Microsoft\Windows NT\Audit';$auditFile=Join-Path $auditDir 'audit.csv'
    $targetDescription="existing GPO '$effectiveGpoName' ($gpoId) in domain '$domainName'";if(-not$PSCmdlet.ShouldProcess($targetDescription,'Configure WSF audit telemetry policy and remove deprecated WINEVT registry values')){Write-Section 'RESULT';Write-Host 'RESULT: WHATIF/PREVIEW validation passed. No GPO content was changed.';exit 0}

    Write-Section 'BACKUP';$backupRoot=Join-Path $env:TEMP ('WSF-GPO-Backup-'+(Get-Date -Format 'yyyyMMdd-HHmmss'));New-Item -ItemType Directory -Path $backupRoot -Force|Out-Null;Backup-GPO -Guid $gpoId -Domain $domainName -Server $pdcName -Path $backupRoot|Out-Null;Write-Host ('Backup path : {0}' -f $backupRoot)
    New-Item -ItemType Directory -Path $securityDir -Force|Out-Null;Write-Utf8NoBom $securityFile $securityTemplate;Register-GpoExtension $nativeDc $gpoId ([guid]'{827D319E-6EAC-11D2-A4EA-00C04F79F83A}') ([guid]'{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}')
    New-Item -ItemType Directory -Path $auditDir -Force|Out-Null;Write-Utf8NoBom $auditFile $auditCsv;Register-GpoExtension $nativeDc $gpoId ([guid]'{F3CCC681-B74C-4060-9F26-CD84525DCA2A}') ([guid]'{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}')
    Set-GPPrefRegistryValue -Guid $gpoId -Domain $domainName -Server $pdcName -Context Computer -Action Update -Key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\Audit' -ValueName 'SpecialGroups' -Type String -Value $specialGroupsValue -Confirm:$false|Out-Null

    Write-Section 'EVENT CHANNEL PREREQUISITES';foreach($channelName in $eventChannels){Write-Host ('{0,-45} : ASSERTED; no GPO registry write' -f $channelName)}
    $legacyChannelKey='HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-NTLM/Operational';foreach($valueName in @('Enabled','MaxSize')){try{Remove-GPRegistryValue -Guid $gpoId -Domain $domainName -Server $pdcName -Key $legacyChannelKey -ValueName $valueName -Confirm:$false -ErrorAction Stop|Out-Null;Write-Host ('Legacy {0,-7}                          : REMOVED FROM GPO' -f $valueName)}catch{if($_.Exception.Message -match '(?i)not found|does not exist|cannot find'){Write-Host ('Legacy {0,-7}                          : ABSENT' -f $valueName)}else{throw}}}

    Write-Section 'VERIFY GPO CONTENT';$verified=Get-GPO -Guid $gpoId -Domain $domainName -Server $pdcName;if(-not(Test-Path $securityFile)){throw 'Verification failed: GptTmpl.inf not found.'};if(-not(Test-Path $auditFile)){throw 'Verification failed: audit.csv not found.'};$writtenAuditRows=@(Import-Csv $auditFile);if($writtenAuditRows.Count -ne $auditRows.Count){throw 'Verification failed: audit.csv row count mismatch.'}
    $reportXmlPath=Join-Path $env:TEMP ('WSF-GPO-Report-'+$gpoId+'.xml');Get-GPOReport -Guid $gpoId -Domain $domainName -Server $pdcName -ReportType Xml -Path $reportXmlPath;[xml]$verifiedReportXml=Get-Content $reportXmlPath -Raw;$reportErrors=@($verifiedReportXml.SelectNodes("//*[local-name()='Error']"));$auditReportErrors=@($reportErrors|Where-Object{$_.InnerText -match '(?i)audit\.csv|Advanced Audit|Auditing|CorruptAuditFile'});if($auditReportErrors.Count -gt 0){throw 'Verification failed: GPMC rejected Advanced Audit Policy audit.csv.'}
    $reportText=Get-Content $reportXmlPath -Raw;if($reportText -match [regex]::Escape($legacyChannelKey)){throw 'Verification failed: deprecated WINEVT channel registry policy remains in the GPO.'}
    Write-Host 'GPO verification         : PASS';Write-Host ('Advanced audit rows      : PASS ({0})' -f $writtenAuditRows.Count);Write-Host 'Event channel writes     : ABSENT (PASS)';Write-Host ('Computer version         : {0}' -f $verified.Computer.DSVersion)
    Write-Section 'RESULT';Write-Host 'Security Options          : WRITTEN';Write-Host 'Advanced Audit Policy     : WRITTEN (21)';Write-Host 'SpecialGroups             : WRITTEN';Write-Host 'Event Channels            : ASSERTED ONLY';Write-Host 'Legacy WINEVT GPO values  : ABSENT';Write-Host 'GPO link operation        : NOT PERFORMED';Write-Host 'gpupdate                  : NOT PERFORMED';Write-Host ('Backup                    : {0}' -f $backupRoot);Write-Host '';Write-Host 'RESULT: WSF audit GPO configuration completed and structural verification passed.';exit 0
}
catch { Write-Host '';Write-Host 'RESULT: FAIL';Write-Host ('ERROR : {0}' -f $_.Exception.Message);exit 1 }
finally { if($null -ne(Get-Variable nativeDc -ErrorAction SilentlyContinue)-and$null -ne$nativeDc){try{$nativeDc.Dispose()}catch{}};if($null -ne(Get-Variable nativeDomain -ErrorAction SilentlyContinue)-and$null -ne$nativeDomain){try{$nativeDomain.Dispose()}catch{}} }
