# Windows Privilege Escalation Matrix

Last updated: 2026-08-06

## Purpose

This document defines the analysis and validation plan for the Windows Privilege Escalation module.

The module must focus on evidence of privilege escalation or abuse of elevated rights. It must not generate generic high-severity alerts for normal administrative activity.

No custom Wazuh rule is approved merely because an event is security-relevant. Each event must first be generated, received by Wazuh, decoded, compared with stock Wazuh coverage and evaluated in its real operational context.

## Planned scope

| Event ID | Log | Meaning | Detection role | Initial priority | Planned validation | Status |
|---:|---|---|---|---|---|---|
| 4672 | Security | Special privileges assigned to a new logon | Enrichment and correlation for privileged sessions | Medium | Reuse the validated Windows Authentication result and correlate by Logon ID where useful | TESTED AS TELEMETRY |
| 4673 | Security | A privileged service was called | Baseline-based detection of unexpected sensitive privilege use | High | Real-event baseline, live Wazuh ingestion, stock-rule review and benign-profile suppression validated; positive alert test still pending | PARTIALLY TESTED |
| 4674 | Security | An operation was attempted on a privileged object | Possible sensitive-object or privilege abuse; potentially noisy | High | Generate controlled ownership/ACL operations and determine whether the event provides actionable context | PLANNED |
| 4688 | Security | A new process was created | Primary process context for escalation chains; not a generic escalation alert | Critical | Process auditing, command-line inclusion, decoded Wazuh fields and stock-rule coverage verified | TESTED |
| 4697 | Security | A service was installed in the system | Persistence or privilege-escalation technique; identifies the installing account | Critical | Controlled service creation, Security log, live Wazuh ingestion, stock-rule search and custom rule validation completed | TESTED – CUSTOM RULE 111000 |
| 7045 | System | A service was installed in the system | Complementary service-installation evidence from the System log | Critical | Compared with Event 4697 and validated against stock Wazuh coverage | TESTED – STOCK RULE 61138 |
| 4964 | Security | Special groups were assigned to a new logon | Enrichment for sensitive group membership in a logon token | Medium | Confirm audit-policy requirements, generate a real event if feasible and evaluate usefulness against 4672 | PLANNED |
| 1102 | Security | The audit log was cleared | Strong anti-forensics indicator | Critical | Perform only as an approved final controlled test; verify stock rule, alert level and email policy | PLANNED |

## Event dispositions

Each event must receive one explicit disposition after testing:

- standalone alert;
- correlation or enrichment only;
- telemetry only;
- intentionally excluded from the module.

Current dispositions:

| Event ID | Disposition |
|---:|---|
| 4672 | Telemetry and correlation enrichment only |
| 4673 | Baseline-based alert for profiles that differ from the verified LocalSystem LSASS pattern; benign-profile suppression tested, positive alert validation pending |
| 4688 | High-volume telemetry and context for narrowly defined detections |
| 4697 | Standalone custom alert, level 10 |
| 7045 | Complementary stock alert, level 5 |

## Validation workflow

For every planned event:

1. Confirm the required Windows Advanced Audit Policy setting.
2. Generate a controlled real event on the selected test host.
3. Confirm the event exists in the authoritative Windows log.
4. Confirm the Wazuh agent forwards it.
5. Inspect the decoded field names and values in Wazuh.
6. Search the active stock Wazuh rules on `server07`.
7. Decide whether stock coverage is sufficient.
8. Add only the minimum necessary custom rule.
9. Validate the rule using another real event.
10. Define alert severity and email policy from observed behavior.
11. Record the result in this matrix and in `PROJECT-STATE.md`.

## Initial test environment

Expected systems:

- Wazuh manager: `server07`;
- Windows test host: `TERMINAL2` unless a server-side event requires another host;
- Active Directory domain: `PCO.CZ`;
- test activity must use controlled accounts and reversible changes.

The Event 4697/7045 validation was performed on `SERVER01.pco.cz`.

## Safety constraints

- Do not test destructive or persistence-related actions on production servers without an explicit rollback procedure.
- Do not clear the Security log until all other event testing is complete and the test is explicitly approved.
- Test services must use harmless commands and must be removed immediately after validation.
- Process-creation rules must not alert solely on common binaries such as `powershell.exe`, `cmd.exe`, `reg.exe`, `net.exe` or `sc.exe`; command line, parent process, user, integrity and surrounding events must be considered.
- Events 4673 and 4674 may be high-volume and must not be enabled or alerted on broadly before noise is measured.
- Event 4672 remains enrichment/correlation telemetry unless a new documented scenario proves that a narrower rule is required.

## Event ID 4673 – Sensitive Privilege Use

### Status

PARTIALLY TESTED

### Required audit policy

Event ID 4673 requires:

```text
Computer Configuration
└── Policies
    └── Windows Settings
        └── Security Settings
            └── Advanced Audit Policy Configuration
                └── Audit Policies
                    └── Privilege Use
                        └── Audit Sensitive Privilege Use
```

Validated setting:

```text
Success: Enabled
```

### Microsoft security guidance

Microsoft documents Event 4673 as a context-dependent sensitive privilege-use event. The recommended monitoring model is not to alert on every event, but to identify deviations from expected combinations of:

- account or security identifier;
- privilege name;
- process name and path;
- service name;
- expected system role and administrative behavior.

Microsoft's reference example uses the same normal system profile observed in this environment:

```text
SubjectUserSid: S-1-5-18
ProcessName: C:\Windows\System32\lsass.exe
Service: LsaRegisterLogonProcess()
PrivilegeList: SeTcbPrivilege
```

This supports a baseline-based design: suppress a fully verified benign profile and alert on other successful Event 4673 profiles for investigation. It does not prove that all non-matching profiles are malicious.

### Observed production baseline

Observed counts from `archives.json`:

- `SERVER01`: 1316 events;
- `server02`: 77 events.

All observed events shared the same profile:

```text
SubjectUserSid: S-1-5-18
SubjectUserName: machine account for the host
ProcessName: C:\\Windows\\System32\\lsass.exe
Service: LsaRegisterLogonProcess()
PrivilegeList: SeTcbPrivilege
```

A 24-hour Windows-log sample on `SERVER01` contained 495 events with this same combination.

A controlled `robocopy /B` test did not generate a different Event 4673 profile. Only the established LSASS/SeTcbPrivilege pattern appeared. This test therefore must not be cited as a positive Event 4673 generation method.

### Stock Wazuh coverage

The active stock ruleset contains rule `60107`:

- parent: `60104` (`AUDIT_FAILURE`);
- Event ID: `4673`;
- level: `4`;
- description: `Failed attempt to perform a privileged operation`.

Therefore, stock rule `60107` covers failed Event 4673 operations only. Successful Event 4673 events are received and archived but do not create a stock alert.

Live ingestion was confirmed in:

```text
/var/ossec/logs/archives/archives.json
```

Verified decoder for live ingestion:

```text
windows_eventchannel
```

### Custom rules

File:

```text
rules/1110-windows-privilege-escalation.xml
```

Rules:

- `111100` – internal base for successful Event 4673;
- `111101` – level 8 alert for a successful Event 4673 profile not suppressed by a known-benign child rule; no email;
- `111102` – level 0 suppression for the verified LocalSystem LSASS profile.

The process-path matcher accepts the escaped path form seen in the live Wazuh data:

```text
C:\\Windows\\System32\\lsass.exe
```

### Negative-path validation

The first suppression regex did not match the live escaped `processName` value, so legitimate LSASS events incorrectly produced rule `111101`. The regex was corrected and redeployed.

After correction:

- new Event 4673 records remained present in `archives.json`;
- the same records no longer carried rule `111101`;
- an OpenSearch query for rule `111101` after `2026-08-06T08:47:00Z` returned zero hits;
- no email notification was generated.

Conclusion: rule `111102` successfully suppresses the verified LocalSystem LSASS baseline.

### Positive-path validation state

Rule `111101` is not yet marked TESTED.

A real successful Event 4673 with a different account, process, service or privilege profile has not yet been generated reproducibly. The failed `robocopy /B` attempt confirmed that speculative test commands must not be treated as validated event-generation procedures.

The next step is to identify a documented and safe operation that reliably generates a non-baseline successful Event 4673, then validate rule `111101` through live Windows EventChannel ingestion.

### Operational conclusion

- Do not create a generic high-severity alert for every Event 4673.
- Use a baseline-based model and treat non-matching profiles as investigation candidates, not automatically as confirmed attacks.
- The verified LSASS profile is suppressed.
- Rule `111101` remains level 8 and without email until a real positive test and production-noise review are complete.

## Event ID 4688 – Process Creation

### Status

TESTED

### Windows validation

Validated on `SERVER01.pco.cz` on 2026-07-30.

- Advanced Audit Policy subcategory `Process Creation`: `Success`.
- Registry value `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled`: enabled.
- Event ID 4688 was generated successfully.
- Process command line was present in the Security event.
- Parent process, subject account, token elevation type and mandatory integrity label were present.
- Controlled test command: `whoami /all`.
- Observed process: `C:\Windows\System32\whoami.exe`.
- Observed parent process: `C:\Windows\System32\cmd.exe`.
- Observed mandatory label: `S-1-16-12288` (`High Mandatory Level`).

### Wazuh validation

- Agent: `SERVER01` (`001`).
- Manager: `server07`.
- Decoder: `windows_eventchannel`.
- Stock rule ID: `67027`.
- Stock rule description: `A process was created.`
- Stock rule level: `3`.
- Stock rule email: disabled.
- Custom decoder: not required.
- Custom base rule for all Event ID 4688 events: not required.

### Verified decoded fields

- `data.win.system.eventID`
- `data.win.eventdata.subjectUserSid`
- `data.win.eventdata.subjectUserName`
- `data.win.eventdata.subjectDomainName`
- `data.win.eventdata.subjectLogonId`
- `data.win.eventdata.newProcessId`
- `data.win.eventdata.newProcessName`
- `data.win.eventdata.tokenElevationType`
- `data.win.eventdata.processId`
- `data.win.eventdata.commandLine`
- `data.win.eventdata.parentProcessName`
- `data.win.eventdata.mandatoryLabel`

### Operational conclusion

Event ID 4688 is high-volume telemetry. The stock Wazuh rule is sufficient as the collection baseline, but level 3 is not intended to identify privilege escalation by itself.

Any later custom detection must use additional context such as command-line arguments, parent process, user, integrity level, Logon ID or surrounding events. A process name alone is not sufficient for a high-severity alert.

## Event IDs 4697 and 7045 – Windows Service Installation

### Status

TESTED

### Required audit policy

Event ID 4697 requires the following Advanced Audit Policy subcategory:

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

Verification command:

```powershell
auditpol /get /subcategory:"Security System Extension"
```

A result of `No Auditing` prevents Windows from generating Event ID 4697. The setting is therefore managed through the `Wazuh Domain Controller Policy` Group Policy rather than as an ad-hoc local change.

### Controlled test

```cmd
sc.exe create WSF-TestService5 binPath= "cmd.exe /c exit"
```

Cleanup:

```cmd
sc.exe delete WSF-TestService5
```

### Windows validation

The controlled test generated:

- Security Event ID `4697`;
- System Event ID `7045`.

Event ID 4697 included the installing identity and service details, including:

- `subjectUserName`;
- `subjectDomainName`;
- `serviceName`;
- `serviceFileName`;
- `serviceType`;
- `serviceStartType`;
- `serviceAccount`.

### Wazuh validation

Both events were received through the `windows_eventchannel` decoder.

Event ID 7045 matched the existing stock rule:

- rule ID: `61138`;
- level: `5`;
- description: `New Windows Service Created`.

No active stock rule matching Windows Security Event ID 4697 was found. The apparent grep matches `44697` and `184697` were unrelated rule IDs.

Custom rule `111000` was created and validated:

- parent rule: `60103` (`Windows audit success event`);
- event: Security Event ID `4697`;
- level: `10`;
- MITRE ATT&CK: `T1543.003`;
- verified description: `Windows service installed by PCO\administrator: WSF-TestService5`.

### Operational conclusion

Events 4697 and 7045 are complementary rather than duplicates:

- 7045 provides stock System-log service-installation detection;
- 4697 provides the installing user identity and is the authoritative security alert for this module.

The custom 4697 alert is retained at level 10. Production noise and notification policy must be reviewed before enabling immediate email delivery.

### Testing note

Pasting EventChannel JSON into `wazuh-logtest` may cause it to be decoded as generic `json` rather than `windows_eventchannel`. The final validation was therefore performed through live Windows EventChannel ingestion and confirmed in `wazuh-alerts-*`.

Detailed documentation:

- `docs/windows-privilege-escalation/event-4697-service-installed.md`
- `rules/1110-windows-privilege-escalation.xml`

## Candidate processes for detailed analysis

The following processes are approved for individual analysis. Approval means they will be tested and evaluated; it does not mean that every execution will generate an alert.

| Process | Detailed analysis | Current status |
|---|---|---|
| `powershell.exe` | YES | PLANNED |
| `pwsh.exe` | YES | PLANNED |
| `cmd.exe` | YES | PLANNED |
| `reg.exe` | YES | PLANNED |
| `net.exe` | YES | PLANNED |
| `net1.exe` | YES | PLANNED |
| `rundll32.exe` | YES | PLANNED |
| `mshta.exe` | YES | PLANNED |
| `cscript.exe` | YES | PLANNED |
| `wscript.exe` | YES | PLANNED |
| `schtasks.exe` | YES | PLANNED |
| `sc.exe` | YES | PLANNED |
| `psexec.exe` | YES | PLANNED |
| `certutil.exe` | YES | PLANNED |
| `whoami.exe` | NO | TEST TOOL ONLY |

## Candidate correlations

The following are hypotheses for later testing, not approved detections:

- privileged logon (4624 + 4672) followed by suspicious process creation (4688) within the same Logon ID;
- explicit credentials (4648) followed by an elevated process or remote administrative action;
- service installation (4697 and/or 7045) followed by execution of the installed service binary;
- suspicious elevated activity followed by Security log clearing (1102).

No correlation will be implemented until the individual source events and decoded fields are validated.

## Notification policy baseline

- No generic email for 4672, 4673, 4674, 4688 or 4964.
- Event 4697 is a level 10 standalone alert. Email remains pending an explicit production-noise review and policy decision.
- Event 7045 remains covered by stock rule 61138 and does not need a duplicate custom rule.
- Security log clearing is a candidate for immediate email, but the final policy must be based on stock-rule behavior and controlled validation.
- Correlation alerts may receive email only after controlled validation and an explicit policy decision.

## Next work item

Identify a documented, safe and reproducible positive test for Event 4673 rule `111101`. Do not mark it TESTED until a real non-baseline Event 4673 is generated and confirmed through live Windows EventChannel ingestion.
