# Windows Authentication

**Version:** 0.2.0

**Status:** In development - baseline partially implemented and tested

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
4. Verify that Wazuh receives and decodes the event.
5. Every custom rule must have a documented purpose and real-event test before it is marked TESTED.
6. Routine authentication activity is retained for investigation and dashboards but does not automatically generate email.
7. Critical or operationally actionable scenarios have an explicit notification policy.

---

## Authentication Event Coverage

| Event ID | Description | Current state | Email policy |
|---:|---|---|---|
| 4624 | Successful logon | Stock rule 60106 identified; production behavior/use cases still to validate | No for ordinary logons |
| 4625 | Failed logon | Stock rules validated; custom incorrect-password classification and same-account/source correlation implemented | Correlated/high-risk cases only |
| 4634 | User logoff | Stock rule 60137 identified; validation pending | No |
| 4648 | Explicit credentials used | Standard rule not found during initial analysis; detailed analysis pending | Selected high-risk cases only |
| 4672 | Special privileges assigned | Standard rule 67028 identified in WEF baseline; target installation validation pending | Selected cases only |
| 4740 | Account locked out | Custom rule 101200 tested against real production event | Yes |
| 4771 | Kerberos pre-authentication failed | Implemented in Kerberos rules; invalid-password, locked/revoked and repeated-failure scenarios tested | Correlated password attack: Yes |

Detailed mapping is maintained in `authentication-matrix.md`.

---

## Implemented rule files

- `rules/1010-windows-authentication_rules.xml`
  - 101000 - incorrect-password classification for Event 4625
  - 101001 - repeated incorrect password for same account and source
- `rules/1011-windows-kerberos-4771.xml`
  - 101100 - internal 4771 base rule
  - 101101 - Kerberos invalid password / status 0x18
  - 101102 - account locked or revoked / status 0x12
  - 101110 - repeated Kerberos invalid-password correlation; email enabled
- `rules/1012-windows-account-lockout.xml`
  - 101200 - authoritative Event 4740 account-lockout notification; email enabled

---

## Related Active Directory management coverage

Active Directory management events are tracked separately from the authentication baseline but are already implemented in this repository:

- `rules/1020-windows-user-management.xml`
- `rules/1021-windows-password-management.xml`
- `rules/1022-windows-privileged-groups.xml`

This includes tested user lifecycle, password management, security-group membership and privileged-group monitoring. The authoritative implementation/test status is recorded in `PROJECT-STATE.md`.

---

## Remaining work for v0.2.0

1. Validate Event 4624 behavior and define which successful-logon scenarios deserve higher-severity detection.
2. Complete Event 4625 failure-reason analysis beyond the current incorrect-password scenario.
3. Validate Event 4634 stock behavior.
4. Analyze Event 4648 and implement a custom rule only if stock coverage is insufficient.
5. Validate Event 4672 and standard rule 67028 on the target Wazuh installation.
6. Synchronize the authentication matrix with real production tests.
7. Implement and validate the Windows Authentication dashboard.
8. Review the complete notification policy before declaring v0.2.0 complete.

---

## Completion rule

The module is not complete merely because events are collected. Every baseline event must have an explicit disposition: standard Wazuh coverage, custom detection, correlation, dashboard-only retention, or intentional exclusion.
