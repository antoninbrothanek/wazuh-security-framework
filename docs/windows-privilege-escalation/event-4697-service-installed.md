# Windows Privilege Escalation – Event ID 4697

## Overview

| Item | Value |
|---|---|
| Windows Event ID | `4697` |
| Event name | A service was installed in the system |
| Log | Security |
| Audit subcategory | Security System Extension |
| MITRE ATT&CK | T1543.003 – Create or Modify System Process: Windows Service |
| Wazuh stock rule | No |
| Custom rule | `111000` |
| Status | Verified |

## Detection objective

Detect installation of a new Windows service from the Security log.

Windows Event ID 7045 in the System log is covered by Wazuh stock rule `61138`, but Event ID 4697 is more valuable for security monitoring because it also records the user account that installed the service.

## Required Windows audit policy

Windows does not generate Event ID 4697 unless the following Advanced Audit Policy subcategory is enabled:

```text
Computer Configuration
└── Policies
    └── Windows Settings
        └── Security Settings
            └── Advanced Audit Policy Configuration
                └── Audit Policies
                    └── System
                        └── Audit Security System Extension
```

Required setting:

```text
Success: Enabled
Failure: Disabled
```

Verification:

```powershell
auditpol /get /subcategory:"Security System Extension"
```

Expected result:

```text
Security System Extension    Success
```

## Test procedure

Create a temporary service from an elevated command prompt:

```cmd
sc.exe create WSF-TestService5 binPath= "cmd.exe /c exit"
```

Remove it after testing:

```cmd
sc.exe delete WSF-TestService5
```

## Expected Windows event

The Security log must contain Event ID `4697` with fields including:

- `subjectUserName`
- `subjectDomainName`
- `serviceName`
- `serviceFileName`
- `serviceType`
- `serviceStartType`
- `serviceAccount`

## Wazuh processing

The live event is decoded by:

```text
windows_eventchannel
```

The event is stored with:

```text
data.win.system.eventID = 4697
```

No stock Wazuh rule was found for Event ID 4697. The existing stock rule `61138` applies to System Event ID 7045 only.

## Custom Wazuh rule

```xml
<group name="windows,windows_security,privilege_escalation,persistence,">

  <!--
    Event ID: 4697
    Windows Security Audit
    A service was installed in the system

    MITRE ATT&CK:
      T1543.003 - Create or Modify System Process: Windows Service

    Prerequisite:
      Advanced Audit Policy ->
      System ->
      Audit Security System Extension = Success
  -->

  <rule id="111000" level="10">
    <if_sid>60103</if_sid>
    <field name="win.system.eventID">^4697$</field>
    <description>Windows service installed by $(win.eventdata.subjectDomainName)\$(win.eventdata.subjectUserName): $(win.eventdata.serviceName)</description>

    <mitre>
      <id>T1543.003</id>
    </mitre>

    <group>
      windows,
      windows_security,
      privilege_escalation,
      persistence,
      service_installation,
    </group>
  </rule>

</group>
```

Recommended manager path:

```text
/var/ossec/etc/rules/windows_privilege_escalation_rules.xml
```

## Verified result

The test service `WSF-TestService5` produced both expected alerts:

| Event ID | Wazuh rule | Level | Result |
|---|---:|---:|---|
| 7045 | 61138 | 5 | Stock alert generated |
| 4697 | 111000 | 10 | Custom alert generated |

Verified custom alert description:

```text
Windows service installed by PCO\administrator: WSF-TestService5
```

## Troubleshooting

If Event ID 7045 is generated but Event ID 4697 is missing, verify the audit policy first:

```powershell
auditpol /get /subcategory:"Security System Extension"
```

A result of `No Auditing` means Windows will not generate Event ID 4697, and Wazuh therefore has no event to process.

When EventChannel JSON is pasted manually into `wazuh-logtest`, it may be decoded as generic `json` rather than `windows_eventchannel`. Validate this rule through live Windows EventChannel ingestion instead of relying only on pasted JSON in `wazuh-logtest`.
