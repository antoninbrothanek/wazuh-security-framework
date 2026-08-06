# Windows Privilege Escalation Matrix

Last updated: 2026-08-06

## Purpose

This document defines the validated state of the Windows Privilege Escalation module.

The module focuses on evidence of privilege escalation or abuse of elevated rights. It must not generate generic high-severity alerts for normal administrative activity.

No custom Wazuh rule is approved merely because an event is security-relevant. Each event must first be generated or observed, received by Wazuh, decoded, compared with stock Wazuh coverage and evaluated in its real operational context.

## Current scope and status

| Event ID | Log | Meaning | Coverage | Status |
|---:|---|---|---|---|
| 4672 | Security | Special privileges assigned to a new logon | stock 67028 | TESTED AS TELEMETRY |
| 4673 | Security | A privileged service was called | stock 60107 for failures; successful events retained as telemetry | ANALYZED – NO GENERIC CUSTOM RULE |
| 4674 | Security | An operation was attempted on a privileged object | telemetry only | ANALYZED – NO GENERIC CUSTOM RULE |
| 4688 | Security | A new process was created | stock 67027, level 3 | TESTED AS TELEMETRY |
| 4697 | Security | A service was installed in the system | custom 111000, level 10 | TESTED – CUSTOM RULE |
| 7045 | System | A service was installed in the system | stock 61138, level 5 | TESTED – STOCK RULE |
| 4964 | Security | Special groups were assigned to a new logon | custom 111201, level 10 | TESTED – CUSTOM RULE |
| 1102 | Security | The Security audit log was cleared | custom 111400, level 12 | TESTED – CUSTOM RULE |
| 4698 | Security | A scheduled task was created | stock 60228, level 4 | TESTED AS TELEMETRY |
| 4703 | Security | A token right was adjusted | no live sample; no stock rule | DEFERRED |
| 4719 | Security | System audit policy was changed | stock 60112, level 8 | TESTED – STOCK RULE |

## Event dispositions

| Event ID | Disposition |
|---:|---|
| 4672 | Telemetry and correlation enrichment only |
| 4673 | Telemetry and customer-specific baseline only; stock failure rule retained; no portable custom success rule |
| 4674 | Telemetry only; no portable generic custom rule |
| 4688 | High-volume telemetry and context for narrowly defined detections |
| 4697 | Standalone custom alert, level 10 |
| 7045 | Complementary stock alert, level 5 |
| 4964 | Standalone custom alert for human logons containing a configured SpecialGroups SID, level 10 |
| 1102 | Standalone custom alert, level 12, immediate email |
| 4698 | Stock telemetry only; no generic custom rule |
| 4703 | Deferred until a real production sample is available |
| 4719 | Stock alert, level 8; no generic email |

## Validation workflow

For every event:

1. Confirm the required Windows Advanced Audit Policy setting where applicable.
2. Generate or observe a real event on the selected host.
3. Confirm the event exists in the authoritative Windows log.
4. Confirm the Wazuh agent forwards it.
5. Inspect the decoded field names and values in Wazuh.
6. Search the active stock Wazuh rules on `server07`.
7. Decide whether stock coverage is sufficient.
8. Add only the minimum necessary custom rule.
9. Validate the rule using another real event.
10. Define alert severity and email policy from observed behavior.
11. Record the result in this matrix, detailed documentation and `PROJECT-STATE.md`.

## Test environment

- Wazuh manager: `server07`;
- Windows hosts used during validation: `SERVER01`, `server02`, `TERMINAL2`, `TERMINALSERVER`;
- Active Directory domain: `PCO.CZ`;
- controlled tests used reversible changes and explicit cleanup.

## Safety constraints

- Do not test destructive or persistence-related actions on production servers without an explicit rollback procedure.
- Test services and scheduled tasks must use harmless commands and must be removed immediately after validation.
- Process-creation rules must not alert solely on common binaries such as `powershell.exe`, `cmd.exe`, `reg.exe`, `net.exe` or `sc.exe`.
- Events 4673 and 4674 must not be elevated generically without a measured customer-specific baseline.
- Event 4672 remains enrichment/correlation telemetry unless a new documented scenario proves that a narrower rule is required.
- Audit policy must not be changed based only on an assumed dependency; inspect live event and stock behavior first.

## Event ID 4673 – Sensitive Privilege Use

### Status

ANALYZED – NO GENERIC CUSTOM RULE

Successful Event 4673 activity was high-volume and context dependent. The validated baseline consisted of LocalSystem/LSASS activity using `LsaRegisterLogonProcess()` and `SeTcbPrivilege`.

Stock rule `60107` covers failed Event 4673 operations. Experimental custom success rules `111100`, `111101` and `111102` were removed because a portable universal allowlist could not be justified.

Final policy:

- no generic custom alert for successful Event 4673;
- no generic email notification;
- retain successful events as telemetry;
- future customer-specific rules require measured baseline data and an explicit approved requirement.

## Event ID 4674 – Privileged Object Operation

### Status

ANALYZED – NO GENERIC CUSTOM RULE

The event was evaluated as context-dependent privileged-object telemetry. No portable generic rule was approved because normal administrative operations can produce legitimate events and the framework does not have a universal sensitive-object allowlist.

Final policy:

- retain as telemetry;
- no generic custom alert;
- no generic email;
- customer-specific detection requires an explicit object scope and measured baseline.

## Event ID 4688 – Process Creation

### Status

TESTED AS TELEMETRY – STOCK RULE 67027

Validated state:

- `Audit Process Creation`: Success;
- `ProcessCreationIncludeCmdLine_Enabled`: enabled;
- command line, parent process and process path decoded correctly;
- stock rule `67027`, level 3, matched live events;
- production baseline showed high-volume legitimate activity from Exchange, Windows, Azure Arc, ESET and other services.

Decision:

- no custom base rule;
- no alert based only on process name;
- no generic email;
- future detections must use specific command-line, parent, user, integrity or correlation context.

Detailed documentation:

- `docs/windows-privilege-escalation/event-4688-process-creation.md`

## Event IDs 4697 and 7045 – Windows Service Installation

### Status

TESTED

Controlled service creation generated both Security Event 4697 and System Event 7045.

- Event 7045 matched stock rule `61138`, level 5.
- Event 4697 had no adequate active stock match and is covered by custom rule `111000`, level 10, MITRE `T1543.003`.

Detailed documentation:

- `docs/windows-privilege-escalation/event-4697-service-installed.md`
- `rules/1110-windows-privilege-escalation.xml`

## Event ID 4964 – Special Groups Assigned to a New Logon

### Status

TESTED – CUSTOM RULE 111201

Validated configuration:

```text
Audit Special Logon: Success
HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Audit\SpecialGroups
REG_SZ: S-1-5-32-544
```

Rules:

- `111200`: internal level 0 base;
- `111201`: level 10 alert for human accounts;
- exclusions: LocalSystem SID `S-1-5-18` and account names ending in `$`;
- generic email disabled.

Detailed documentation:

- `docs/windows-privilege-escalation/event-4964-special-groups.md`
- `rules/1110-windows-privilege-escalation.xml`

## Event ID 1102 – Security Audit Log Cleared

### Status

TESTED – CUSTOM RULE 111400

Validated behavior:

- stock rule `63103`, level 5, matched the live event;
- custom child rule `111400`, level 12, matched successfully;
- alert description includes host and account identity;
- immediate email notification was delivered;
- MITRE ATT&CK: `T1070.001`.

Notification policy:

- immediate email enabled.

## Event ID 4698 – Scheduled Task Created

### Status

TESTED AS TELEMETRY – STOCK RULE 60228

Validated behavior:

- stock rule `60228`, level 4;
- live events observed from Lenovo Vantage, OneDrive and SoftLanding;
- no generic custom rule;
- no generic email;
- suspicious-task detections belong to a separately approved persistence work item.

Detailed documentation:

- `docs/windows-privilege-escalation/event-4698-scheduled-task-created.md`

## Event ID 4703 – Token Right Adjusted

### Status

DEFERRED

Validated state:

- `Authorization Policy Change`: Success;
- no Event 4703 observed in live archives;
- no active stock Windows rule found;
- no artificial test program will be introduced solely to force this event.

Reopen only after obtaining a real production sample.

Detailed documentation:

- `docs/windows-privilege-escalation/event-4703-token-right-adjusted.md`

## Event ID 4719 – System Audit Policy Changed

### Status

TESTED – STOCK RULE 60112

Controlled test:

- temporarily enabled `Other Object Access Events` success auditing;
- immediately restored the original `No Auditing` state;
- Windows generated both `Success added` and `Success removed` events;
- Wazuh matched stock rule `60112`, level 8;
- no custom rule and no generic email.

Detailed documentation:

- `docs/windows-privilege-escalation/event-4719-audit-policy-changed.md`

## Notification policy baseline

- No generic email for 4672, 4673, 4674, 4688, 4697, 4698, 4703, 4719 or 4964.
- Event 7045 remains covered by stock rule 61138 and does not need a duplicate custom rule.
- Event 1102 custom rule 111400 sends immediate email.
- Future correlation alerts may receive email only after controlled validation and an explicit policy decision.

## Next work item

The event baseline through Event 4719 is synchronized. The next work item must be selected from the updated project state and roadmap before implementation begins.
