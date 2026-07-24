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
| Successful logon | 4624 | 60106 | 3 | None currently | IDENTIFIED - validation and use-case review pending | Yes | No for ordinary logons |
| Failed logon | 4625 | 60105 / 60122 | 5 | 101000, 101001 | PARTIALLY TESTED - incorrect-password scenario implemented; remaining failure reasons to review | Yes | Correlated/high-risk cases only |
| User logoff | 4634 | 60137 | 3 | None | IDENTIFIED - real-event validation pending | No | No |
| Explicit credentials used | 4648 | Not found during initial analysis | — | Not yet implemented | ANALYSIS REQUIRED | Yes | Selected high-risk cases only |
| Special privileges assigned | 4672 | 67028 in WEF baseline | 3 | None currently | IDENTIFIED - verify rule is loaded and suitable on target Wazuh | Yes | Selected cases only |
| Account lockout | 4740 | 60115 | 9 | 101200 | TESTED | Yes | Yes - immediate operational/security notification |
| Kerberos pre-authentication failure | 4771 | Base handling via Windows Security rules | varies | 101100, 101101, 101102, 101110 | TESTED for implemented 0x18 / 0x12 / repeated-failure scenarios | Planned in Kerberos milestone | Email for correlated password attack |

---

## Detailed decisions

### 4624 - Successful logon

Standard rule `60106` is the expected baseline rule.

Ordinary successful logons are retained for investigation and dashboard analysis and do not generate email.

Before adding custom detection, the framework must validate real 4624 events and decide which scenarios are operationally useful. Possible candidates are documented only as investigation topics, not approved features:

- privileged-account logon,
- RDP logon,
- unusual source workstation,
- unusual source IP address,
- logon outside an approved time window.

No custom 4624 rule is approved until a concrete scenario is validated and documented.

### 4625 - Failed logon

Standard Wazuh coverage uses rules `60105` / `60122` depending on event details.

Current custom rules in `rules/1010-windows-authentication_rules.xml`:

- `101000` - Event 4625, correct username with incorrect password (`status 0xc000006d`, `subStatus 0xc000006a`).
- `101001` - correlation for repeated incorrect passwords against the same account from the same source IP.

Individual routine failures do not generate email.

The 4625 event family is not yet complete. Remaining work is to classify relevant status/subStatus combinations and decide for each whether it is:

- dashboard-only,
- operationally useful,
- security-relevant,
- correlation input,
- intentionally ignored.

No additional custom rule is created until the corresponding real event and stock-rule behavior are verified.

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

This rule has been confirmed with a real production lockout event and email notification.

Event 4771 status `0x12` is not used as the authoritative lockout notification because it can repeat for subsequent authentication attempts against an already locked, disabled, or revoked account.

### 4771 - Kerberos pre-authentication failure

Kerberos is tracked as its own roadmap milestone, but its implemented rules are listed here because they are part of the overall authentication chain.

Current rules in `rules/1011-windows-kerberos-4771.xml`:

- `101100` - internal Event 4771 base rule.
- `101101` - status `0x18`, invalid password / stale credentials.
- `101102` - status `0x12`, locked or revoked account scenario.
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

1. **4624** - validate successful-logon stock behavior and decide approved use cases.
2. **4625** - finish failed-logon status/subStatus classification.
3. **4634** - validate stock logoff behavior.
4. **4648** - analyze real explicit-credential events and stock coverage.
5. **4672** - validate real event and standard rule 67028.
6. Update this matrix after each verified result.
7. Implement and validate the Windows Authentication dashboard.
8. Review notification policy and documentation.
9. Mark v0.2.0 complete only when all baseline scenarios have an explicit tested or intentionally excluded disposition.

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
