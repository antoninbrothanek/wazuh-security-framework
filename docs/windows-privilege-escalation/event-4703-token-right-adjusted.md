# Event 4703 – Token Right Adjusted

## Status

DEFERRED

## Scope

Windows Security Event ID 4703 records a process dynamically enabling or disabling privileges in an access token.

## Verified configuration

The following Advanced Audit Policy setting was verified on `SERVER01`:

```text
Policy Change
  Authorization Policy Change: Success
```

Verification command:

```powershell
auditpol /get /subcategory:"Authorization Policy Change"
```

## Wazuh stock-rule search

The active Wazuh ruleset on `server07` was searched for Event ID 4703.

Observed matches were unrelated numeric rule IDs from FortiMail and osquery rule files. No active stock Windows EventChannel rule matching Event ID 4703 was found.

## Live-data validation

The Wazuh archives were searched for Event ID 4703:

```bash
grep '"eventID":"4703"' \
  /var/ossec/logs/archives/archives.json
```

No Event ID 4703 record was found.

## Technical conclusion

Event ID 4703 is generated when a process changes token privileges through Windows token-adjustment mechanisms such as `AdjustTokenPrivileges()`.

The event was not observed in the validated environment despite the relevant audit policy being enabled. No artificial test program was created solely to force the event.

## Framework decision

- no custom WSF rule is implemented;
- no generic email notification is enabled;
- no assumptions are made about decoded field names without a real event;
- the event remains deferred until a real production or laboratory sample is captured;
- the item must be reopened before any rule implementation.

This decision follows the development contract: evidence is required before implementing a portable detection rule.
