# Windows Authentication

**Version:** 0.2.0

**Status:** COMPLETE - baseline event analysis, target-manager validation, dashboard implementation and notification-policy review completed

---

## Purpose

The Windows Authentication module monitors authentication events in Active Directory environments.

Its purpose is to detect security-relevant authentication activity while minimizing false positives and avoiding unnecessary email noise.

The module focuses on domain-wide authentication rather than individual server monitoring.

---

## Design principles

1. Prefer standard Wazuh rules when they provide sufficient detection and context.
2. Create custom rules only when standard coverage is insufficient.
3. Verify the Windows event with a real event before implementing a custom rule.
4. Verify that Wazuh receives and decodes the event before relying on it for detection.
5. Every custom rule must have a documented purpose and real-event test before it is marked TESTED.
6. Routine authentication activity is retained for investigation and dashboards but does not automatically generate email.
7. Critical or operationally actionable scenarios have an explicit notification policy.
8. Windows Security Event Log is the source of truth during controlled event analysis; Wazuh processing is validated afterwards.

---

## Authentication Event Coverage

| Event ID | Description | Current state | Email policy |
|---:|---|---|---|
| 4624 | Successful logon | Stock rule 60106 tested with real production events | No |
| 4625 | Failed logon | Stock rules validated; custom rules 101000, 101001 and 101002 tested with controlled real events | No for 101000/101001/101002 |
| 4634 | User logoff | Intentionally excluded from the v0.2.0 detection baseline; no security requirement demonstrated | No |
| 4648 | Explicit credentials used | Real Windows behavior validated; no stock alerting coverage found on server07; no generic custom alert approved | No generic email |
| 4672 | Special privileges assigned | Real Windows behavior validated; stock rule 67028 confirmed on server07 with a real event; enrichment/correlation only | No generic email |
| 4740 | Account locked out | Custom rule 101200 tested against real production and controlled events | Yes - 101200 |
| 4771 | Kerberos pre-authentication failed | Implemented in Kerberos rules; invalid-password, locked/revoked and repeated-failure scenarios tested | Only repeated attack correlation 101110 |
| 4776 | NTLM credential validation | Observed during controlled NTLM failures; retained as NTLM-specific authentication telemetry; no new custom rule approved in v0.2.0 | No generic email |

Detailed mapping is maintained in `authentication-matrix.md`.

---

## Final notification policy

The production rule review on `server07` confirmed the final v0.2.0 email policy:

| Rule | Meaning | Level | Email |
|---:|---|---:|---|
| 101000 | Event 4625 incorrect password | 5 | No |
| 101001 | Repeated Event 4625 incorrect password for same account/source | 8 | No |
| 101002 | Event 4625 nonexistent username | 5 | No |
| 101101 | Kerberos invalid password / status 0x18 | 5 | No |
| 101102 | Kerberos account locked or revoked / status 0x12 | 7 | No |
| 101110 | Repeated Kerberos invalid-password attack correlation | 10 | Yes - `alert_by_email` |
| 101200 | Authoritative Event 4740 account lockout | 9 | Yes - `alert_by_email` |

The policy deliberately avoids email for ordinary authentication failures and for the 101001 repeated-4625 correlation because those events are useful for dashboards and investigation but can be operationally noisy. Email is reserved for the stronger repeated Kerberos attack correlation and authoritative account lockout event.

Historical `.bak-*` rule files are not authoritative. Notification-policy validation is based on the currently active `.xml` files in `/var/ossec/etc/rules/`.

---

## Implemented rule files

- `rules/1010-windows-authentication_rules.xml`
  - 101000 - incorrect-password classification for Event 4625; TESTED
  - 101001 - repeated incorrect password for same account and source; TESTED; no email
  - 101002 - nonexistent-username classification for Event 4625; TESTED; no email
- `rules/1011-windows-kerberos-4771.xml`
  - 101100 - internal 4771 base rule
  - 101101 - Kerberos invalid password / status 0x18; no email
  - 101102 - account locked or revoked / status 0x12; no email
  - 101110 - repeated Kerberos invalid-password correlation; email enabled
- `rules/1012-windows-account-lockout.xml`
  - 101200 - authoritative Event 4740 account-lockout notification; email enabled

### Verified Event 4625 behavior

Controlled tests on 2026-07-25 confirmed:

- Event 4625 with `status 0xc000006d` and `subStatus 0xc000006a` reaches stock rule `60122` and then matches custom rule `101000`.
- Rule `101000` correctly includes `targetUserName` and `ipAddress` in the alert description.
- Three matching `101000` events within 300 seconds for the same username and source IP trigger correlation rule `101001`.
- Rule `101001` was observed at level 8 with the expected account and source context.
- A controlled nonexistent username `WazuhNoSuchUser` generated Event 4625 with `status 0xc000006d`, `subStatus 0xc0000064`, NTLM, Logon Type 3, workstation `TERMINAL2`, source `192.168.150.140`.
- The same event matched custom rule `101002` at level 5 with the expected username and source IP in the alert description.
- Event 4740 generated by the controlled lockout sequence matched existing rule `101200`.
- Event 4776 was observed alongside NTLM authentication attempts, including statuses `0xc000006a` and `0xc0000234`; no new 4776 rule was added during this work.

The earlier 101000 failure was caused by unnecessary field-presence conditions using `.+`. Removing those conditions allowed the status/subStatus classification to match correctly.

### Verified Event 4648 behavior

Controlled testing on `TERMINAL2` confirmed that Event 4648 provides distinct context about explicit credential use.

Observed examples included:

- `SubjectUser=kerberos01`, `TargetUser=administrator`, `TargetServer=localhost` during explicit local credential use.
- `SubjectUser=kerberos01`, `TargetUser=administrator`, `TargetServer=server01`, source/destination context `192.168.150.2:445` during SMB access using explicit credentials.
- legitimate local elevation/UAC activity using `consent.exe`, demonstrating that Event 4648 alone must not be treated as malicious.

Target-manager validation on `server07` confirmed:

- no Event 4648 alert was present in `wazuh-alerts-*` for the controlled samples;
- the loaded stock/custom rulesets contained no Windows rule explicitly matching Event ID 4648;
- the only grep hit for `4648` was unrelated FortiMail rule ID `44648`;
- `wazuh-archives-*` is not indexed on this installation, so archive-index verification is unavailable.

Decision: retain 4648 as security-relevant telemetry and use it only for documented high-risk detections or correlation. Do not create a generic custom alert solely because stock alerting coverage is absent.

### Verified Event 4672 behavior

Controlled testing on `TERMINAL2` with `PCO\administrator` confirmed Event 4672 and the assigned sensitive privilege list, including `SeSecurityPrivilege`, `SeTakeOwnershipPrivilege`, `SeBackupPrivilege`, `SeRestorePrivilege`, `SeDebugPrivilege`, and `SeImpersonatePrivilege`.

The Event 4672 `SubjectLogonId` matched the Event 4624 `TargetLogonId` (`0x364a5812`) for the same administrator logon.

Target-manager validation on `server07` confirmed stock rule `67028` in `0955-WEF-baseline_rules.xml`:

- Event ID 4672;
- level 3;
- excludes LocalSystem SID `S-1-5-18`;
- description `Special privileges assigned to new logon.`

A real controlled `TERMINAL2` Event 4672 for `PCO\administrator` matched rule `67028`. A second legitimate sample from `server02` for machine account `SERVER01$` also matched the same rule, reinforcing that 4672 is normal privileged-logon telemetry rather than a standalone incident.

Decision: 4672 is an enrichment/correlation event for identifying privileged logons. Stock rule 67028 is sufficient; no custom rule and no generic email are required.

### Event 4634 disposition

A controlled check did not produce a useful Event 4634 sample for the tested session. Because logoff has low standalone detection value and no current security requirement depends on it, further 4634 testing is intentionally deferred and it is excluded from the v0.2.0 detection baseline.

---

## Windows Authentication Security dashboard

The dashboard `Windows Authentication Security` was implemented and validated on 2026-07-27 using the `wazuh-alerts-*` index pattern.

Validated panels:

- `Windows Auth - Failed Logons` - Event ID 4625 count.
- `Windows Auth - Repeated Failed Logons` - custom rule 101001 count.
- `Windows Auth - Unknown Usernames` - custom rule 101002 count.
- `Windows Auth - Account Lockouts` - custom rule 101200 count.
- `Windows Auth - Top Failed Usernames` - Event ID 4625 grouped by `data.win.eventdata.targetUserName`.
- `Windows Auth - Top Failed Source IPs` - Event ID 4625 grouped by `data.win.eventdata.ipAddress`.
- `Windows Auth - Authentication Failures Timeline` - Event ID 4625 over time.
- `Windows Auth - Kerberos Failures` - split metric for rules 101101, 101102 and 101110 with labels `Kerberos invalid password`, `Kerberos account locked or revoked`, and `Repeated Kerberos failures`.
- `Top Privileged User Accounts` - stock rule 67028 grouped by `data.win.eventdata.subjectUserName`.

For `Top Privileged User Accounts`, machine accounts and LocalSystem noise are removed at the Terms aggregation level using the validated Exclude expression:

`(.*\$|SYSTEM)`

This filtering is intentionally applied to the visualization bucket rather than to the global DQL query. The dashboard therefore retains rule `67028` as the source while presenting human privileged-account activity without machine-account domination.

The dashboard is intended for investigation and operational visibility. Its presence does not change the module's email-notification policy.

---

## Related Active Directory management coverage

Active Directory management events are tracked separately from the authentication baseline but are already implemented in this repository:

- `rules/1020-windows-user-management.xml`
- `rules/1021-windows-password-management.xml`
- `rules/1022-windows-privileged-groups.xml`

This includes tested user lifecycle, password management, security-group membership and privileged-group monitoring. The authoritative implementation/test status is recorded in `PROJECT-STATE.md`.

---

## v0.2.0 completion

Windows Authentication v0.2.0 is complete as of 2026-07-27 for the defined scope. Every baseline event has an explicit disposition: stock coverage, tested custom detection, correlation/enrichment, dashboard/telemetry retention, or intentional exclusion. The final production notification-policy review confirmed that only rules 101110 and 101200 explicitly generate authentication email notifications.
