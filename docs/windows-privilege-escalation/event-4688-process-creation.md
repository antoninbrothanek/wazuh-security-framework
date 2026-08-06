# Event ID 4688 — Process Creation

Last updated: 2026-08-06

## Status

`TESTED AS TELEMETRY — STOCK RULE 67027`

## Purpose

Event ID 4688 records process creation in the Windows Security log. In the portable Wazuh Security Framework it is retained as high-volume process telemetry and as a parent data source for future narrowly defined detections.

The framework does not create a generic alert merely because a common administrative binary was started.

## Verified Windows configuration

The following settings were verified on `SERVER01.pco.cz`:

```text
Advanced Audit Policy
Detailed Tracking
Audit Process Creation: Success
```

Command-line recording was also verified:

```text
HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
ProcessCreationIncludeCmdLine_Enabled
Type: REG_DWORD
Value: 1
```

## Verified Wazuh ingestion

Live events were received through:

```text
decoder: windows_eventchannel
```

The active stock rule is:

```text
Rule ID: 67027
Level: 3
Description: A process was created.
Parent: 60103
Provider: Microsoft-Windows-Security-Auditing
Event ID: 4688
Email: disabled
```

Active rule source:

```text
/var/ossec/ruleset/rules/0955-WEF-baseline_rules.xml
```

A custom base rule is not required.

## Verified decoded fields

The live data included at least:

- `win.eventdata.newProcessName`;
- `win.eventdata.parentProcessName`;
- `win.eventdata.commandLine`;
- process and parent-process context from the Security event.

Command-line data was present in the archived events.

## Measured baseline

The measured process inventory showed substantial legitimate activity from Windows, Exchange, security software and management agents.

Examples included:

- `cmd.exe` launched by `MSExchangeHMWorker.exe` for Exchange health checks;
- `nslookup.exe`, `nltest.exe` and `netsh.exe` used by Exchange;
- `powershell.exe` used by Azure Connected Machine Agent;
- `appcmd.exe` used by ESET automatic exclusions;
- `auditpol.exe`, `SecEdit.exe` and PowerShell used by the Wazuh agent;
- Windows Update and servicing processes;
- print, WMI, Edge Update and other normal system processes.

Observed high-volume processes included:

```text
conhost.exe
cmd.exe
nslookup.exe
nltest.exe
svchost.exe
netsh.exe
relog.exe
powershell.exe
```

This baseline proves that process name alone is insufficient for a portable high-severity rule.

## Framework decision

Event 4688 is closed for the first implementation stage with the following disposition:

```text
Collection: enabled
Command line: enabled
Stock Wazuh rule: retained
Custom generic rule: no
Generic email: no
Disposition: baseline telemetry
```

The framework must not create generic alerts solely for execution of common binaries such as:

- `cmd.exe`;
- `powershell.exe`;
- `reg.exe`;
- `net.exe`;
- `net1.exe`;
- `sc.exe`;
- `nslookup.exe`;
- `nltest.exe`;
- `curl.exe`.

## Future detections

Any later custom rule based on Event 4688 must target a specific verified behavior and use sufficient context, such as:

- command-line arguments;
- parent process;
- user or service account;
- executable path;
- integrity or elevation context;
- Logon ID;
- surrounding events.

Examples such as encoded PowerShell or a specific LOLBin technique remain future candidates only. They are not implemented or marked as tested by this document.

## Final result

Stock rule `67027` provides the required baseline collection. No additional portable rule is justified for Event 4688 itself.
