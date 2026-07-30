# Windows Privilege Escalation

## Scope

This module validates and implements detections for Windows events that may indicate privilege escalation, abuse of elevated rights, persistence or anti-forensics activity.

The module follows the project validation workflow:

1. Enable and verify the required Windows audit policy.
2. Generate a controlled real event.
3. Confirm the event in the authoritative Windows log.
4. Confirm Wazuh ingestion and decoded fields.
5. Review active stock Wazuh rules.
6. Add a custom rule only when stock coverage is insufficient.
7. Validate the final rule with another real event.
8. Document severity and notification policy.

## Current verified coverage

| Event ID | Meaning | Coverage | Status |
|---:|---|---|---|
| 4672 | Special privileges assigned to a new logon | Stock rule 67028; telemetry/correlation | Tested |
| 4688 | A new process was created | Stock rule 67027; telemetry/context | Tested |
| 4697 | A service was installed in the system | Custom rule 111000, level 10 | Tested |
| 7045 | A service was installed in the system | Stock rule 61138, level 5 | Tested |

## Implemented files

- `rules/1110-windows-privilege-escalation.xml`
- `modules/windows-privilege-escalation/privilege-escalation-matrix.md`
- `docs/windows-privilege-escalation/event-4697-service-installed.md`

## Event 4697 prerequisite

Event ID 4697 requires the Advanced Audit Policy subcategory:

```text
System -> Audit Security System Extension -> Success
```

The setting is managed through Group Policy. Without it, Windows generates Event ID 7045 but does not generate Security Event ID 4697.

## Current policy

- Event 4672 is not a standalone incident; it is enrichment for privileged logons.
- Event 4688 is high-volume telemetry and requires additional context before any high-severity custom detection is approved.
- Event 4697 is the primary service-installation security alert because it identifies the account that installed the service.
- Event 7045 remains useful complementary stock coverage.
- No generic rule is created solely because an event is security-relevant.

## Next work

Continue only with the next explicitly selected event from the matrix. Validate Windows generation, Wazuh ingestion and stock-rule behavior before implementing another custom rule.
