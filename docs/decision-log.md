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

---

### 2026-08-06
**Module:** Windows Privilege Escalation

**Decision:** Retain Event ID 4688 as stock telemetry using rule `67027`. Do not create generic alerts based only on common process names.

**Reason:** The measured baseline contained high-volume legitimate activity from Windows, Exchange, Azure Arc, ESET and other services. Process names such as `powershell.exe`, `cmd.exe`, `net.exe`, `sc.exe` and `curl.exe` are not independently sufficient indicators.

**Evidence:**

- `Audit Process Creation` enabled;
- command-line inclusion enabled;
- live Wazuh ingestion and decoded process, parent and command-line fields confirmed;
- stock rule `67027`, level 3, matched real events;
- measured production process baseline reviewed.

**Result:** Accepted. Event 4688 is telemetry and context for narrowly defined future detections. No generic email.

---

### 2026-08-06
**Module:** Windows Privilege Escalation

**Decision:** Use custom rule `111400`, level 12, with immediate email for Security Event ID 1102.

**Reason:** Clearing the Security audit log is a strong anti-forensics event. Stock rule `63103`, level 5, was considered insufficient for the selected notification policy.

**Evidence:**

- controlled `Clear-EventLog -LogName Security` test;
- live decoder fields confirmed, including `win.logFileCleared.subjectUserName` and domain;
- rule `111400` matched a real event;
- alert level 12 and `mail: true` confirmed;
- email notification delivered successfully.

**Result:** Accepted. Immediate email remains enabled for rule `111400`.

---

### 2026-08-06
**Module:** Windows Privilege Escalation

**Decision:** Retain Event ID 4698 as stock telemetry using rule `60228`. Do not create a generic scheduled-task child rule.

**Reason:** Real events included legitimate Lenovo Vantage, OneDrive and SoftLanding tasks. A portable generic rule would require environment-specific allowlists or suspicious action criteria not yet approved.

**Evidence:**

- live Event 4698 ingestion from `TERMINALSERVER` and `TERMINAL2`;
- stock rule `60228`, level 4, matched the events;
- task-name baseline reviewed.

**Result:** Accepted. No generic custom rule and no generic email. Persistence-specific detection requires a separate approved work item.

---

### 2026-08-06
**Module:** Windows Privilege Escalation

**Decision:** Defer Event ID 4703 until a real production sample is available.

**Reason:** The relevant audit policy was enabled, but no Event 4703 was found in live archives and no active stock Windows rule was identified. The project will not introduce an artificial program solely to force the event.

**Evidence:**

- `Authorization Policy Change`: Success;
- archive search returned no Event 4703;
- active stock-rule search returned no Windows Event 4703 match.

**Result:** Accepted. No custom rule and no email. Reopen only with a real sample.

---

### 2026-08-06
**Module:** Windows Privilege Escalation

**Decision:** Use stock rule `60112`, level 8, for Event ID 4719. Do not add a duplicate child rule or generic email.

**Reason:** The stock rule correctly detected both enabling and restoring a test audit subcategory and included the responsible account and policy-change context.

**Evidence:**

- controlled change of `Other Object Access Events` from `No Auditing` to Success and back;
- Windows generated `Success added` and `Success removed` Event 4719 records;
- Wazuh matched rule `60112`, level 8, for both events;
- original audit state was restored.

**Result:** Accepted. Stock coverage retained without generic email.

---

### 2026-08-06
**Module:** Windows Privileged Group Management

**Decision:** Do not perform separate laboratory tests for rules `102202` (Print Operators) and `102203` (Replicator).

**Reason:** Both rules use the same already validated parent-rule and matching structure as the other privileged-group rules. Their only material difference is the monitored group identifier. Repeating the same add-member test would not validate a new mechanism or add meaningful technical evidence.

**Alternatives:**

- individually add a test user to Print Operators and Replicator;
- leave both rules indefinitely marked as pending individual tests.

Both alternatives were rejected as unnecessary repetition.

**Evidence:**

- six sibling privileged-group rules were validated with real membership changes;
- the shared rule structure, severity and email behavior are already confirmed;
- rules `102202` and `102203` differ only in their target group matching data.

**Result:** Accepted. The rules remain implemented; separate laboratory validation is intentionally not planned.

---

### 2026-08-06
**Module:** Project Roadmap

**Decision:** Close Windows Privilege Escalation for its approved scope and activate NTLM Monitoring v0.4.0 as the next milestone.

**Reason:** All approved Windows Privilege Escalation events have a validated or explicit disposition. Event 4703 is deliberately deferred and does not block completion. NTLM Monitoring is the next explicitly selected project module.

**Evidence:**

- synchronized `PROJECT-STATE.md`, roadmap and privilege-escalation documentation;
- tested stock and custom behavior through Event 4719;
- explicit user approval to begin NTLM Monitoring.

**Result:** Accepted. NTLM work begins with scope definition and evidence collection. No NTLM custom rule is approved yet.
