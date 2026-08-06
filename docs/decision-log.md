# Decision Log

This document records important architectural and technical decisions.

## Template
- Date
- Module
- Decision
- Reason
- Alternatives
- Evidence
- Result

## Entries

### 2026-07-30
**Module:** Windows Privilege Escalation

**Decision:** Do not create a generic detection rule for Event ID 4673.

**Reason:** Initial testing showed legitimate LSASS activity repeatedly generates Event ID 4673 with SeTcbPrivilege.

**Evidence:** Laboratory testing on Windows Server 2019.

**Result:** Accepted.

---

### 2026-08-06
**Module:** Windows Privilege Escalation

**Decision:** Remove experimental custom rules `111100`, `111101` and `111102` for successful Event ID 4673. Retain Event 4673 as telemetry and customer-specific baseline material only. Use stock rule `60107` for failed privileged operations.

**Reason:** Successful Event 4673 is high-volume and context dependent. The tested environment produced only the legitimate LocalSystem LSASS profile (`S-1-5-18`, `LsaRegisterLogonProcess()`, `SeTcbPrivilege`). A generic "anything else" rule would depend on organization-specific allowlists and could create false positives when deployed to other companies. A safe, documented and reproducible positive test for a portable non-baseline rule was not established.

**Alternatives:**

- alert on every successful Event 4673;
- retain a default alert with a hard-coded LSASS suppression rule;
- build a separate Sensitive Privilege Use module with multiple baseline rules.

All alternatives were rejected for the portable framework baseline. Customer-specific rules may be introduced later only after measuring the target environment and approving an explicit requirement.

**Evidence:**

- live EventChannel ingestion from `SERVER01` and `server02`;
- 24-hour sample of 495 identical LSASS events on `SERVER01`;
- stock Wazuh rule `60107` confirmed for `AUDIT_FAILURE` Event 4673;
- successful events confirmed in `/var/ossec/logs/archives/archives.json`;
- controlled `robocopy /B` tests did not produce a different Event 4673 profile;
- experimental suppression logic was tested but proved environment-specific rather than universally portable.

**Result:** Accepted. No generic custom Event 4673 rule and no generic email notification.
