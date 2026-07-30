# Windows Privilege Escalation Matrix

Last updated: 2026-07-30

## Purpose

This document defines the initial analysis and validation plan for the Windows Privilege Escalation module.

The module must focus on evidence of privilege escalation or abuse of elevated rights. It must not generate generic high-severity alerts for normal administrative activity.

No custom Wazuh rule is approved merely because an event is security-relevant. Each event must first be generated, received by Wazuh, decoded, compared with stock Wazuh coverage and evaluated in its real operational context.

## Planned scope

| Event ID | Log | Meaning | Detection role | Initial priority | Planned validation | Status |
|---:|---|---|---|---|---|---|
| 4672 | Security | Special privileges assigned to a new logon | Enrichment and correlation for privileged sessions | Medium | Reuse the validated Windows Authentication result and correlate by Logon ID where useful | TESTED AS TELEMETRY |
| 4673 | Security | A privileged service was called | Possible abuse of sensitive privileges; context dependent | High | Enable required audit policy, generate controlled events and inspect decoded fields and stock rules | PLANNED |
| 4674 | Security | An operation was attempted on a privileged object | Possible sensitive-object or privilege abuse; potentially noisy | High | Generate controlled ownership/ACL operations and determine whether the event provides actionable context | PLANNED |
| 4688 | Security | A new process was created | Primary process context for escalation chains; not a generic escalation alert | Critical | Process auditing, command-line inclusion, decoded Wazuh fields and stock-rule coverage verified | TESTED |
| 4697 | Security | A service was installed in the system | Persistence or privilege-escalation technique; legitimate administration also possible | Critical | Create and remove a controlled test service; inspect Security log and stock Wazuh coverage | PLANNED |
| 7045 | System | A service was installed in the system | Independent service-installation evidence from the System log | Critical | Compare with Event 4697, confirm collection and decide which event is authoritative or complementary | PLANNED |
| 4964 | Security | Special groups were assigned to a new logon | Enrichment for sensitive group membership in a logon token | Medium | Confirm audit-policy requirements, generate a real event if feasible and evaluate usefulness against 4672 | PLANNED |
| 1102 | Security | The audit log was cleared | Strong anti-forensics indicator | Critical | Perform only as an approved final controlled test; verify stock rule, alert level and email policy | PLANNED |

## Event dispositions to determine

Each event must receive one explicit disposition after testing:

- standalone alert;
- correlation or enrichment only;
- telemetry only;
- intentionally excluded from the module.

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

## Safety constraints

- Do not test destructive or persistence-related actions on production servers without an explicit rollback procedure.
- Do not clear the Security log until all other event testing is complete and the test is explicitly approved.
- Test services must use harmless commands and must be removed immediately after validation.
- Process-creation rules must not alert solely on common binaries such as `powershell.exe`, `cmd.exe`, `reg.exe`, `net.exe` or `sc.exe`; command line, parent process, user, integrity and surrounding events must be considered.
- Events 4673 and 4674 may be high-volume and must not be enabled or alerted on broadly before noise is measured.
- Event 4672 remains enrichment/correlation telemetry unless a new documented scenario proves that a narrower rule is required.

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
- Service installation and Security log clearing are candidates for immediate email, but the final policy must be based on stock-rule behavior and production noise.
- Correlation alerts may receive email only after controlled validation and an explicit policy decision.

## Next work item

Continue with controlled Event ID 4688 process scenarios. Begin with `powershell.exe`, then evaluate `cmd.exe` as an explicitly approved analysis target.

Before creating any custom process rule:

1. generate a controlled benign process event;
2. inspect the Windows XML;
3. inspect the Wazuh-decoded document;
4. identify normal administrative noise;
5. define a specific suspicious scenario;
6. create a custom rule only when the stock rule cannot express the approved scenario.