# Windows Authentication

**Version:** 0.2.0

**Status:** Draft

---

## Purpose

The Windows Authentication module monitors authentication events in Active Directory environments.

Its purpose is to detect security-relevant authentication activity while minimizing false positives.

The module focuses on domain-wide authentication rather than individual server monitoring.

---

## Objectives

- Monitor successful authentication.
- Detect failed authentication attempts.
- Detect privileged logons.
- Detect account lockouts.
- Detect explicit credential usage.
- Detect suspicious authentication patterns.

---

## Event Coverage

| Event ID | Description | Status |
|----------|-------------|--------|
| 4624 | Successful Logon | Planned |
| 4625 | Failed Logon | Planned |
| 4634 | Logoff | Planned |
| 4648 | Explicit Credentials | Planned |
| 4672 | Special Privileges Assigned | Planned |
| 4740 | Account Locked Out | Planned |

---

## Deliverables

This module will contain:

- Detection rules
- Dashboards
- Email notifications
- Test scenarios
- Documentation

---

## Design Rule

No detection rule is implemented before its purpose has been documented.