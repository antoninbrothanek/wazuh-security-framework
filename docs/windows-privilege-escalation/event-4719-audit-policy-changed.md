# Event ID 4719 – System Audit Policy Was Changed

## Status

TESTED — STOCK RULE 60112

## Purpose

Event ID 4719 records a change to the Windows system audit policy. The event is security-relevant because audit-policy changes may reduce visibility into later activity, but legitimate administrative and Group Policy operations can also generate the event.

## Audit policy

Validated on `SERVER01.pco.cz`:

```text
Policy Change
  Audit Policy Change    Success
```

Verification command:

```powershell
auditpol /get /subcategory:"Audit Policy Change"
```

## Controlled test

The subcategory `Other Object Access Events` was selected because its initial state was:

```text
No Auditing
```

The test changed only that subcategory and immediately restored the original state.

Enable Success auditing:

```powershell
auditpol /set /subcategory:"Other Object Access Events" /success:enable
```

Restore the original state:

```powershell
auditpol /set /subcategory:"Other Object Access Events" /success:disable /failure:disable
```

Post-test verification confirmed:

```text
Other Object Access Events    No Auditing
```

## Windows event validation

Two Event ID 4719 records were generated:

```text
2026-08-06 14:57:18
User: PCO\administrator
CategoryId: %%8274
SubcategoryId: %%12804
SubcategoryGuid: {0cce9227-69ae-11d9-bed3-505054503030}
AuditPolicyChanges: %%8449
```

```text
2026-08-06 14:57:25
User: PCO\administrator
CategoryId: %%8274
SubcategoryId: %%12804
SubcategoryGuid: {0cce9227-69ae-11d9-bed3-505054503030}
AuditPolicyChanges: %%8448
```

The decoded Wazuh values were:

```text
Success added
Success removed
```

## Stock Wazuh coverage

The active EventChannel ruleset contains:

```xml
<rule id="60112" level="8">
  <if_sid>60103</if_sid>
  <field name="win.system.eventID">^612$|^643$|^4719$|^4907$|^4912$|^4719$</field>
  <description>Windows Audit Policy changed</description>
  <options>no_full_log</options>
</rule>
```

Validated live results on `server07`:

```text
Rule: 60112
Level: 8
Description: Windows Audit Policy changed
Agent: SERVER01
User: PCO\administrator
AuditPolicyChanges: Success added
```

```text
Rule: 60112
Level: 8
Description: Windows Audit Policy changed
Agent: SERVER01
User: PCO\administrator
AuditPolicyChanges: Success removed
```

## Decision

The stock Wazuh rule is sufficient for the portable framework baseline.

Final policy:

- keep stock rule `60112`;
- do not create a duplicate custom rule;
- do not enable generic email notification;
- retain Event 4719 as a level 8 audit-policy-change alert with account and subcategory context;
- create a narrower custom rule only if a future approved requirement defines a specific high-risk subcategory or change direction.

## Final disposition

```text
Event ID: 4719
Status: TESTED — STOCK RULE 60112
Custom rule: No
Generic email: No
```
