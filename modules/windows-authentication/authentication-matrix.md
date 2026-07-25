# Windows Authentication Matrix

Version: 0.2.0  
Status: In development - synchronized with current tested state

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

- **TESTED** - confirmed with a real Windows event received and processed by Wazuh.
- **PARTIALLY TESTED** - some scenarios are confirmed, but the event family is not fully classified.
- **IDENTIFIED** - expected stock Wazuh coverage has been located, but target production behavior still needs validation.
- **ANALYSIS REQUIRED** - event behavior and/or stock coverage must be investigated before implementation.

---

## Authentication scenarios

| Scenario | Windows Event ID | Standard Wazuh SID | Standard level | Custom rule(s) | Current status | Dashboard | Email policy |
|---|---:|---:|---:|---|---|---|---|
| Successful logon | 4624 | 60106 | 3 | None | TESTED | Yes | No |
| Failed logon | 4625 | 60105 / 60122 | 5 | 101000 TESTED, 101001 TESTED, 101002 validation pending | PARTIALLY TESTED - incorrect-password classification and same-account/source correlation verified | Yes | Correlated/high-risk cases only |
| User logoff | 4634 | 60137 | 3 | None | IDENTIFIED - real-event validation pending | No | No |
| Explicit credentials used | 4648 | Not found during initial analysis | — | Not yet implemented | ANALYSIS REQUIRED | Yes | Selected high-risk cases only |
| Special privileges assigned | 4672 | 67028 in WEF baseline | 3 | None currently | IDENTIFIED - verify rule is loaded and suitable on target Wazuh | Yes | Selected cases only |
| Account lockout | 4740 | 60115 | 9 | 101200 | TESTED | Yes | Yes - immediate operational/security notification |
| Kerberos pre-authentication failure | 4771 | Base handling via Windows Security rules | varies | 101100, 101101, 101102, 101110 | TESTED for implemented 0x18 / 0x12 / repeated-failure scenarios | Planned in Kerberos milestone | Email for correlated password attack |

---

## Detailed decisions

### 4624 - Successful logon

Status: **TESTED**

Production validation on `SERVER01` confirmed:

- Windows Event ID 4624 is generated normally.
- Wazuh receives and decodes the event using `windows_eventchannel`.
- Stock Wazuh rule `60106` matches the event.
- Stock rule level is 3.
- `mail` is false.
- No generic custom rule is required.

Relevant decoded fields confirmed in production include:

- `win.eventdata.targetUserName`
- `win.eventdata.targetDomainName`
- `win.eventdata.targetUserSid`
- `win.eventdata.logonType`
- `win.eventdata.logonProcessName`
- `win.eventdata.authenticationPackageName`
- `win.eventdata.ipAddress`
- `win.eventdata.ipPort`
- `win.eventdata.elevatedToken`

Observed legitimate production examples included:

- service/system logons,
- machine-account network logons,
- normal user network logons,
- Kerberos authentication,
- NTLM authentication,
- Exchange HealthMailbox activity.

Event 4624 is high-volume authentication telemetry. Ordinary successful logons are retained for investigation, correlation, and dashboard analysis and do not generate email.

No generic custom 4624 alert is approved.

Targeted detections may later use 4624 as input only when a concrete security scenario is separately validated and documented. Investigation topics include:

- RDP / RemoteInteractive logon,
- privileged-account logon,
- NTLM usage,
- unusual source workstation or IP address,
- successful logon following repeated failures.

Important production exception:

Exchange HealthMailbox accounts generate legitimate Event 4624 activity, including **Logon Type 8**. Therefore Logon Type 8 alone must **not** be classified as malicious and must not generate a high-severity email alert without additional context.

### 4625 - Failed logon

Status: **PARTIALLY TESTED**

Stock Wazuh processing has been verified on `SERVER01`:

- `60104` classifies Windows audit failures.
- `60105` classifies Event 4625 as Windows Logon Failure.
- `60122` produces the observed level 5 generic alert `Logon Failure - Unknown user or bad password`.
- The Windows EventChannel decoder exposes `status`, `subStatus`, username, source IP, workstation, logon type, and authentication package for classification and correlation.

Real production and controlled-test observations:

| Status | SubStatus | Observed meaning | Validation |
|---|---|---|---|
| `0xc000006d` | `0xc0000064` | Username does not exist | CONTROLLED WINDOWS EVENT OBSERVED - `WazuhNoSuchUser`, NTLM, Logon Type 3; custom 101002 post-fix validation pending |
| `0xc000006d` | `0xc000006a` | Existing account, incorrect password | CONTROLLED TEST - `wazuh4738`, NTLM, Logon Type 3; custom 101000 TESTED |
| `0xc000006e` | `0xc0000071` | Password expired | OBSERVED IN PRODUCTION |
| `0xc000006e` | `0xc0000072` | Account disabled | OBSERVED IN PRODUCTION; sample generated locally by `MSExchangeMailboxAssistants.exe` with an empty target username |
| `0xc000035b` | `0x0` | NTLM/SSPI failure requiring contextual interpretation | OBSERVED IN PRODUCTION - do not classify automatically as an attack |

The disabled-account sample is an important false-positive warning: Event 4625 can be generated by a legitimate local application/service process. `status/subStatus` alone is therefore not sufficient to assign security severity.

Current custom rules in `rules/1010-windows-authentication_rules.xml` include:

- `101000` - classification for Event 4625 with correct username and incorrect password (`status 0xc000006d`, `subStatus 0xc000006a`); TESTED.
- `101001` - correlation for repeated `101000` events against the same account from the same source IP; TESTED.
- `101002` - classification for Event 4625 where the username does not exist (`status 0xc000006d`, `subStatus 0xc0000064`); implemented, post-fix validation pending.

Controlled real-event testing on 2026-07-25 confirmed:

- a real 4625 record reached stock rule `60122` and then matched custom rule `101000`;
- rule 101000 produced level 5 with username `wazuh4738` and source IP `192.168.150.140` in the description;
- three matching 101000 events within the configured 300-second window for the same username and source IP triggered rule `101001`;
- rule 101001 produced the expected level 8 correlation alert;
- the controlled sequence later generated Event 4740, which matched rule `101200`;
- Event 4776 was observed alongside the same NTLM authentication attempts with statuses `0xc000006a` and `0xc0000234`; this observation did not add or approve a new 4776 rule.

The earlier 101000 failure was caused by unnecessary field-presence checks using `.+`. Those checks did not behave as intended in the Wazuh rule expression context. Removing them allowed the status/subStatus match to work. Temporary diagnostic rule 101099 confirmed chaining from stock rule 60122 and was removed after the test.

Therefore:

- stock 4625 detection is working,
- custom rule 101000 is validated,
- correlation rule 101001 is validated,
- custom rule 101002 remains implemented but must not be marked TESTED until a new controlled nonexistent-username event matches it,
- routine individual 4625 failures do not generate email.

The next 4625 task is the focused validation of 101002, not expansion of the failure-code taxonomy.

### 4634 - User logoff

Standard rule `60137` has been identified.

Expected policy:

- retain only if useful for investigation/session context,
- no routine email,
- no custom rule unless real testing demonstrates a requirement.

Real-event validation is still pending.

### 4648 - Explicit credentials used

Windows Event ID 4648 was not found in the initially inspected standard ruleset.

This does **not** yet mean that a custom rule must be created automatically.

Required sequence:

1. Generate and inspect a real 4648 event.
2. Verify that Wazuh receives and decodes it.
3. Re-check the loaded stock ruleset on the target manager.
4. Define which 4648 scenarios are security-relevant.
5. Add a custom rule only if stock coverage is insufficient.

Email is reserved for documented high-risk cases, not for every 4648 event.

### 4672 - Special privileges assigned

Rule `67028` was identified in `0955-WEF-baseline_rules.xml`.

Before relying on it, the framework must verify on the target Wazuh manager:

- that the ruleset file is loaded,
- that rule 67028 is enabled,
- that a real 4672 event matches it,
- that its level and context are suitable.

No custom rule is approved before this validation.

### 4740 - Account lockout

Standard rule `60115` detects account lockout.

Custom rule `101200` in `rules/1012-windows-account-lockout.xml` is the framework notification rule:

- Event ID 4740,
- level 9,
- `alert_by_email`,
- description includes the locked username.

This rule has been confirmed with a real production lockout event and again during the controlled 4625 correlation test.

Event 4771 status `0x12` is not used as the authoritative lockout notification because it can repeat for subsequent authentication attempts against an already locked, disabled, or revoked account.

### 4771 - Kerberos pre-authentication failure

Kerberos is tracked as its own roadmap milestone, but its implemented rules are listed here because they are part of the overall authentication chain.

Current rules in `rules/1011-windows-kerberos-4771.xml`:

- `101100` - internal Event 4771 base rule.
- `101101` - status `0x18`, invalid password / stale credentials.
- `101102` - account locked or revoked / status `0x12`.
- `101110` - repeated invalid-password correlation for the same account and source; level 10; email enabled.

These implemented scenarios have been tested. Additional Kerberos failure codes remain a later Kerberos-scope review and must not be added while the current Windows Authentication baseline is being closed.

---

## Notification policy

Current policy for Windows Authentication:

| Category | Email |
|---|---|
| Normal successful logon | No |
| Single routine failed logon | No |
| Repeated/correlated authentication attack | Yes when explicitly configured |
| Account lockout | Yes |
| Ordinary logoff | No |
| Explicit credential use | Only selected high-risk scenarios after analysis |
| Special privilege assignment | Only selected scenarios after validation |

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
- explicit-credential events if retained,
- privileged-logon/special-privilege events if retained.

Dashboard scope must not be expanded before event-classification decisions are complete.

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

Work must proceed in this order:

1. **4625** - validate custom rule `101002` with a new controlled nonexistent-username event.
2. **4634** - validate stock logoff behavior.
3. **4648** - analyze real explicit-credential events and stock coverage.
4. **4672** - validate real event and standard rule 67028.
5. Update this matrix after each verified result.
6. Implement and validate the Windows Authentication dashboard.
7. Review notification policy and documentation.
8. Mark v0.2.0 complete only when all baseline scenarios have an explicit tested or intentionally excluded disposition.

---

## Development rule

For every new authentication scenario:

1. Verify the Windows event exists.
2. Verify Wazuh receives the event.
3. Check the loaded stock Wazuh rules.
4. Define the purpose and notification policy.
5. Add only the required custom rule.
6. Test with a real event.
7. Mark the scenario TESTED only after confirmation.
