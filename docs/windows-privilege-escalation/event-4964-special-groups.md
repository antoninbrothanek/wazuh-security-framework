# Event ID 4964 – Special Groups Assigned to a New Logon

## Status

TESTED – CUSTOM RULE 111201

## Purpose

Event ID 4964 records a new logon whose token contains one or more groups configured in the Windows `SpecialGroups` registry value.

The mechanism is useful for monitoring interactive or remote logons by members of selected privileged groups. The list of monitored groups is defined by Group Policy and is not hard-coded in the Wazuh rule.

## Required audit policy

Event ID 4964 requires:

```text
Computer Configuration
└── Policies
    └── Windows Settings
        └── Security Settings
            └── Advanced Audit Policy Configuration
                └── Audit Policies
                    └── Logon/Logoff
                        └── Audit Special Logon
```

Validated setting:

```text
Success: Enabled
Failure: Disabled
```

Verification command:

```powershell
auditpol /get /subcategory:"Special Logon"
```

## SpecialGroups configuration

The monitored groups are configured through Group Policy Preferences:

```text
Computer Configuration
└── Preferences
    └── Windows Settings
        └── Registry
```

Registry item:

```text
Action:     Update
Hive:       HKEY_LOCAL_MACHINE
Key path:   SYSTEM\CurrentControlSet\Control\Lsa\Audit
Value name: SpecialGroups
Value type: REG_SZ
```

The value contains one or more group SIDs separated by semicolons.

The following baseline was laboratory validated:

```text
S-1-5-32-544
```

This is the SID of `Builtin\Administrators`.

Verification command:

```powershell
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Audit" |
Select-Object SpecialGroups
```

## Recommended group baseline

### Default portable baseline

```text
Builtin\Administrators
SID: S-1-5-32-544
```

### Recommended Active Directory extension

Organizations should consider adding the SIDs of:

- Domain Admins;
- Enterprise Admins;
- Schema Admins;
- customer-specific Tier 0 administrative groups.

The Wazuh Security Framework does not hard-code domain-specific SIDs. Each customer must obtain and configure the SIDs from its own Active Directory.

Example lookup:

```powershell
Get-ADGroup "Domain Admins" | Select-Object Name,SID
Get-ADGroup "Enterprise Admins" | Select-Object Name,SID
Get-ADGroup "Schema Admins" | Select-Object Name,SID
```

Example value format:

```text
S-1-5-32-544;S-1-5-21-<DOMAIN-SID>-512;S-1-5-21-<ROOT-DOMAIN-SID>-518;S-1-5-21-<ROOT-DOMAIN-SID>-519
```

## Laboratory validation

Validated on 2026-08-06 in domain `PCO.CZ`.

Test sequence:

1. `Audit Special Logon` was confirmed as enabled for success events.
2. `SpecialGroups` was configured through `Wazuh Domain Controller Policy` as `REG_SZ` with value `S-1-5-32-544`.
3. Group Policy was applied.
4. The domain `Administrator` account logged on to `server02.pco.cz`.
5. Windows generated Security Event ID 4964.
6. Wazuh received and decoded the event through `windows_eventchannel`.

Verified event fields:

```text
TargetUserName: administrator
TargetDomainName: PCO
TargetUserSid: S-1-5-21-3244488161-1769690587-3059601223-500
TargetLogonId: 0x20a927a4
SidList: %{S-1-5-32-544}
```

The `Subject*` fields identify the system context that processed the logon. The security description and Wazuh rule must use the `Target*` fields for the logged-on account.

## Stock Wazuh coverage

No active stock or custom rule matching Event ID 4964 was found before implementation.

The event was present in:

```text
/var/ossec/logs/archives/archives.json
```

but no alert was generated.

## Custom Wazuh rules

File:

```text
rules/1110-windows-privilege-escalation.xml
```

Rules:

- `111200` – internal level 0 base rule for Event ID 4964;
- `111201` – level 10 alert for a human account whose token contains a configured special group.

Rule `111201` excludes:

- `TargetUserSid = S-1-5-18`;
- target account names ending in `$`.

These exclusions suppress normal LocalSystem and computer-account activity while retaining privileged human logons.

Verified alert description:

```text
Special-group logon by PCO\Administrator: %{S-1-5-32-544}
```

## Positive-path validation

A new logon of `PCO\Administrator` on `server02` generated rule `111201`, level 10.

Multiple Event 4964 records may be generated for separate logon sessions. These are separate Windows events and are not deduplicated by the framework.

## Negative-path validation

The following profiles remained in `archives.json` without rule `111201`:

- `NT AUTHORITY\SYSTEM`;
- `PCO\SERVER01$`;
- `PCO\SERVER02$`;
- LocalSystem records represented by SID `S-1-5-18`.

The negative path therefore correctly suppresses system and computer-account noise.

## Operational policy

- Rule level: 10.
- Generic email notification: disabled pending customer-specific operational review.
- The configured `SpecialGroups` value defines the scope of the detection.
- Adding more groups can increase alert volume and must be approved by the customer.
- Domain-specific group SIDs belong in Group Policy configuration, not in the portable Wazuh XML rule.
