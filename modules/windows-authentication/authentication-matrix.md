# Windows Authentication Matrix

Version: 0.2.0  
Status: In development - event analysis and target-manager validation synchronized with current tested state

## Purpose

This document maps Windows authentication security scenarios to standard Wazuh rules and identifies where custom detection, correlation, dashboards, or email notification are required.

The framework prefers standard Wazuh rules. Custom rules are created only when the standard ruleset does not provide sufficient detection, correlation, severity, or operational context.

`PROJECT-STATE.md` is the authoritative source for implementation and test status.

---

## Compatibility

Initial development and testing:

- Wazuh Manager: 4.14.x
- Windows log source: Security EventChannel
- Primary standard rulesets:
  - `0580-win-security_rules.xml`
  - `0955-WEF-baseline_rules.xml`

Standard Wazuh rule IDs, levels, descriptions, decoder availability, and local rule-ID conflicts must be validated before deploying this module to another Wazuh installation.

---

## Status model

- **TESTED** - confirmed with a real Windows event and, where applicable, real Wazuh processing.
- **OBSERVED / TELEMETRY** - event behavior is confirmed, but no standalone alert is required in the current baseline.
- **INTENTIONALLY EXCLUDED** - investigated and excluded from the current baseline because no useful standalone detection requirement exists.

---

## Authentication scenarios

| Scenario | Windows Event ID | Standard Wazuh SID | Standard level | Custom rule(s) | Current status | Dashboard | Email policy |
|---|---:|---:|---:|---|---|---|---|
| Successful logon | 4624 | 60106 | 3 | None | TESTED | Yes | No |
| Failed logon | 4625 | 60105 / 60122 | 5 | 101000, 101001, 101002 | TESTED for implemented classifications/correlation | Yes | Correlated/high-risk cases only |
| User logoff | 4634 | 60137 identified | 3 | None | INTENTIONALLY EXCLUDED from v0.2.0 detection baseline | No | No |
| Explicit credentials used | 4648 | No stock alerting coverage found on server07 | — | None approved | TESTED for Windows behavior / no generic Wazuh alert | Yes, as selective telemetry | Selected high-risk cases only |
| Special privileges assigned | 4672 | 67028 | 3 | None | TESTED - real event matched stock rule 67028 on server07 | Yes, as enrichment | No generic email |
| Account lockout | 4740 | 60115 | 9 | 101200 | TESTED | Yes | Yes |
| Kerberos pre-authentication failure | 4771 | Windows Security handling + custom rules | varies | 101100, 101101, 101102, 101110 | TESTED for implemented scenarios | Planned | Correlated password attack: Yes |
| NTLM credential validation | 4776 | Standard Windows/Wazuh telemetry | varies | None approved | OBSERVED during controlled NTLM failures | Optional telemetry | No generic email |

---

## Detailed decisions

### 4624 - Successful logon

Status: **TESTED**

Production validation confirmed:

- Windows Event ID 4624 is generated normally.
- Wazuh receives and decodes the event using `windows_eventchannel`.
- Stock Wazuh rule `60106` matches the event.
- Stock rule level is 3.
- No generic custom rule is required.

Relevant decoded fields include:

- `win.eventdata.targetUserName`
- `win.eventdata.targetDomainName`
- `win.eventdata.targetUserSid`
- `win.eventdata.logonType`
- `win.eventdata.logonProcessName`
- `win.eventdata.authenticationPackageName`
- `win.eventdata.ipAddress`
- `win.eventdata.ipPort`
- `win.eventdata.elevatedToken`

Event 4624 is high-volume authentication telemetry. Ordinary successful logons are retained for investigation, correlation, and dashboards and do not generate email.

Exchange HealthMailbox activity is a known legitimate source of unusual-looking logon patterns, including Logon Type 8. Logon type alone must not determine maliciousness.

### 4625 - Failed logon

Status: **TESTED for implemented v0.2.0 classifications and correlation**

Verified Wazuh processing:

- `60105` classifies Event 4625 as Windows Logon Failure.
- `60122` produces the observed level 5 generic alert `Logon Failure - Unknown user or bad password`.
- The EventChannel decoder exposes `status`, `subStatus`, username, source IP, workstation, logon type, and authentication package.

Verified/observed combinations:

| Status | SubStatus | Meaning / context | Validation |
|---|---|---|---|
| `0xc000006d` | `0xc0000064` | Username does not exist | CONTROLLED TEST; custom 101002 TESTED |
| `0xc000006d` | `0xc000006a` | Existing account, incorrect password | CONTROLLED TEST; custom 101000 TESTED |
| `0xc000006e` | `0xc0000071` | Password expired | OBSERVED IN PRODUCTION |
| `0xc000006e` | `0xc0000072` | Account disabled | OBSERVED IN PRODUCTION; legitimate local-service context possible |
| `0xc000035b` | `0x0` | NTLM/SSPI failure requiring context | OBSERVED IN PRODUCTION |

Current custom rules in `rules/1010-windows-authentication_rules.xml`:

- `101000` - incorrect-password classification; TESTED.
- `101001` - repeated incorrect-password correlation for same account/source; TESTED.
- `101002` - nonexistent-username classification; TESTED.

Controlled testing on 2026-07-25 confirmed:

- `101000` matched a real 4625 with `status=0xc000006d`, `subStatus=0xc000006a`.
- three matching events within 300 seconds triggered `101001` at level 8.
- the sequence generated Event 4740 and matched `101200`.
- `WazuhNoSuchUser` generated Event 4625 with `status=0xc000006d`, `subStatus=0xc0000064`, NTLM, Logon Type 3, workstation `TERMINAL2`, source `192.168.150.140`.
- that event matched `101002` at level 5 with the expected username and source IP in the alert description.
- Event 4776 was observed in parallel during NTLM failures with statuses including `0xc000006a`, `0xc0000064` and `0xc0000234`.

The previous matching problem in 101000/101002 was caused by unnecessary `.+` field-presence checks. Removing them restored the intended status/subStatus classification behavior.

### 4634 - User logoff

Status: **INTENTIONALLY EXCLUDED from the v0.2.0 detection baseline**

Stock rule `60137` is known, but a controlled session-close check did not produce a useful Event 4634 sample for the tested session.

Decision:

- no custom rule,
- no routine email,
- no further testing required for v0.2.0,
- revisit only if a future concrete session-correlation requirement depends on it.

### 4648 - Explicit credentials used

Status: **TESTED for Windows behavior; no generic stock/custom alert**

Controlled Windows testing on `TERMINAL2` confirmed that Event 4648 contains security-relevant context not present in a generic 4624 alone.

Observed controlled examples:

1. Explicit local credential use:
   - `SubjectUser=kerberos01`
   - `TargetUser=administrator`
   - `TargetServer=localhost`
   - process context via `svchost.exe`

2. Explicit credentials used against SMB target:
   - `SubjectUser=kerberos01`
   - `TargetUser=administrator`
   - `TargetServer=server01`
   - `IpAddress=192.168.150.2`
   - `IpPort=445`

3. Legitimate UAC/elevation noise:
   - `SubjectUser=TERMINAL2$`
   - `TargetUser=Administrator`
   - `TargetServer=localhost`
   - `Process=consent.exe`

Target-manager validation on `server07` established:

- no controlled Event 4648 appeared in `wazuh-alerts-*`;
- no loaded stock/custom rule explicitly matches Windows Event ID 4648;
- the only grep result for text `4648` was unrelated FortiMail rule ID `44648`;
- `wazuh-archives-*` is not indexed on this manager, so archive-index confirmation is unavailable.

Decision:

- Event 4648 has unique detection/enrichment value for explicit credential use and possible lateral movement.
- Do **not** alert on every 4648 event.
- Candidate high-value conditions include `SubjectUser != TargetUser`, non-local target, remote service ports, privileged target accounts, and correlation with later activity.
- Absence of stock alerting coverage does not by itself justify a generic custom rule.
- No generic custom 4648 rule is approved in v0.2.0.

### 4672 - Special privileges assigned

Status: **TESTED on Windows and target Wazuh manager**

Controlled testing on `TERMINAL2` with `PCO\administrator` produced Event 4672 with sensitive privileges including:

- `SeSecurityPrivilege`
- `SeTakeOwnershipPrivilege`
- `SeLoadDriverPrivilege`
- `SeBackupPrivilege`
- `SeRestorePrivilege`
- `SeDebugPrivilege`
- `SeSystemEnvironmentPrivilege`
- `SeImpersonatePrivilege`
- `SeDelegateSessionUserImpersonatePrivilege`

The Event 4672 `SubjectLogonId=0x364a5812` matched the related Event 4624 `TargetLogonId=0x364a5812` for the same administrator logon.

This experimentally confirms the intended relationship:

`4624 successful logon -> same Logon ID -> 4672 sensitive privileges assigned`

Target-manager validation on `server07` confirmed stock rule `67028` in `0955-WEF-baseline_rules.xml`:

```xml
<rule id="67028" level="3">
  <if_sid>60103</if_sid>
  <field name="win.system.eventID">^4672$</field>
  <field name="win.eventdata.subjectUserSid" negate="yes">^S-1-5-18$</field>
  <description>Special privileges assigned to new logon.</description>
</rule>
```

Confirmed real Wazuh matches:

- `TERMINAL2` / `PCO\administrator`, SID ending `-500`, Logon ID `0x364a5812` -> rule `67028`, level 3.
- `server02` / machine account `SERVER01$` -> rule `67028`, level 3.

Decision:

- 4672 is useful primarily as correlation/enrichment for a privileged logon.
- It is not a generic standalone alert because legitimate administrator and machine-account sessions generate it normally.
- Stock rule `67028` is loaded and suitable on the validated target manager.
- No custom rule and no generic email are required.

### 4740 - Account lockout

Status: **TESTED**

Custom rule `101200` in `rules/1012-windows-account-lockout.xml` is the authoritative framework notification rule:

- Event ID 4740,
- level 9,
- `alert_by_email`,
- description includes the locked username.

It has been confirmed with production and controlled events.

### 4771 - Kerberos pre-authentication failure

Status: **TESTED for implemented scenarios**

Current rules in `rules/1011-windows-kerberos-4771.xml`:

- `101100` - internal Event 4771 base rule.
- `101101` - status `0x18`, invalid password / stale credentials.
- `101102` - locked/revoked-account scenario, status `0x12`.
- `101110` - repeated invalid-password correlation; level 10; email enabled.

Controlled testing established that a failed Kerberos authentication with an intentionally wrong password generated Event 4771 without a corresponding 4625 in that scenario. Therefore 4771 is not redundant with 4625 and has independent Kerberos detection value.

### 4776 - NTLM credential validation

Status: **OBSERVED / TELEMETRY**

Controlled NTLM testing showed 4776 alongside failed NTLM authentication activity, including:

- `0xc000006a` - bad password,
- `0xc0000064` - unknown user,
- `0xc0000234` - locked account.

Decision:

- 4776 is NTLM-specific credential-validation telemetry.
- It is not treated as a duplicate of Kerberos 4771.
- No new generic custom 4776 rule is approved in v0.2.0 because the current 4625/4740 logic already covers the required failure/lockout detections.

---

## Notification policy

| Category | Email |
|---|---|
| Normal successful logon | No |
| Single routine failed logon | No |
| Repeated/correlated authentication attack | Yes when explicitly configured |
| Account lockout | Yes |
| Ordinary logoff | No |
| Explicit credential use | Only future documented high-risk scenarios; no generic email |
| Special privilege assignment | No generic email; use only as correlation/enrichment |
| NTLM credential validation | No generic email |

The global Wazuh email threshold does not replace per-rule policy. Critical or operationally actionable custom rules may explicitly use `<options>alert_by_email</options>`.

---

## Dashboard policy

The Windows Authentication dashboard is still pending.

The dashboard should be built only after baseline event classification is complete so that visualization reflects intentional detections rather than raw event volume.

Expected baseline inputs:

- successful logons,
- failed logons,
- correlated failed-authentication scenarios,
- account lockouts,
- explicit-credential telemetry where available,
- privileged-logon enrichment through stock rule `67028`.

---

## Portability requirements

Before deployment to another Wazuh manager, verify:

1. Required standard rule files.
2. Required standard rule IDs.
3. Expected rule levels and descriptions.
4. Windows EventChannel decoder availability.
5. Local rule ID conflicts.
6. Email configuration and notification threshold.
7. Required event auditing is enabled on Windows/Active Directory systems.

Deployment must stop if required dependencies are missing or differ materially from the validated environment.

---

## Remaining work for Windows Authentication v0.2.0

1. Implement and validate the Windows Authentication dashboard.
2. Review notification policy and final documentation.
3. Mark v0.2.0 complete after dashboard/final-review completion criteria are satisfied.

---

## Development rule

For every new authentication scenario:

1. Verify the Windows event exists in the Windows Security Event Log.
2. Verify Wazuh receives the event.
3. Check the loaded stock Wazuh rules.
4. Define the purpose and notification policy.
5. Add only the required custom rule.
6. Test with a real event.
7. Mark the scenario TESTED only after confirmation.