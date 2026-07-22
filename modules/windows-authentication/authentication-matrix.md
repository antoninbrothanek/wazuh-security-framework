# Windows Authentication Matrix

Version: 0.2.0  
Status: Draft

## Purpose

This document maps Windows authentication security scenarios to standard
Wazuh rules and identifies areas where custom detection rules are required.

The framework prefers standard Wazuh rules. Custom rules are created only
when the standard ruleset does not provide sufficient detection or context.

## Compatibility

Initial development and testing:

- Wazuh Manager: 4.14.x
- Windows log source: Security EventChannel
- Primary standard ruleset:
  - `0580-win-security_rules.xml`
  - `0955-WEF-baseline_rules.xml`

Standard Wazuh rule IDs must be validated before deploying this module to
another Wazuh installation.

## Authentication Scenarios

| Scenario | Windows Event ID | Standard Wazuh SID | Level | Dashboard | Email | Custom Rule |
|---|---:|---:|---:|---|---|---|
| Successful logon | 4624 | 60106 | 3 | Yes | No | No |
| Failed logon | 4625 | 60105 / 60122 | 5 | Yes | No | Correlation only |
| User logoff | 4634 | 60137 | 3 | No | No | No |
| Explicit credentials used | 4648 | Not found | — | Yes | Selected cases | Yes |
| Special privileges assigned | 4672 | 67028 | 3 | Yes | Selected cases | Possibly |
| Account lockout | 4740 | 60115 | 9 | Yes | Yes | No |

## Design Decisions

### Successful logons

Successful logons are retained for investigation and dashboard analysis.

A standard successful logon does not generate an email notification.

Higher-severity detections may be created for situations such as:

- privileged account logon,
- RDP logon,
- unusual source workstation,
- unusual source IP address,
- logon outside an approved time window.

### Failed logons

Individual failed logons do not generate email notifications.

Email notifications are generated only for correlated security scenarios,
for example:

- repeated failures against one account,
- repeated failures from one source,
- failures against multiple accounts,
- successful logon following repeated failures.

### Account lockout

Account lockout is considered operationally and security relevant.

Standard rule `60115` is used as the primary detection and should generate
an email notification.

### Explicit credentials

Windows Event ID 4648 was not found in the inspected standard ruleset.

A custom rule is therefore required, but email notification will be enabled
only for selected high-risk scenarios.

### Special privileges

Windows Event ID 4672 is covered by rule `67028` in the WEF baseline ruleset.

The framework must verify whether this rule is loaded on the target Wazuh
installation before relying on it.

## Portability Requirements

Before deployment, the target Wazuh manager must be checked for:

1. Required standard rule files.
2. Required standard rule IDs.
3. Expected rule levels and descriptions.
4. Windows EventChannel decoder availability.
5. Local rule ID conflicts.

Deployment must stop if required dependencies are missing.