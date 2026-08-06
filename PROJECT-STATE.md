# Wazuh Security Framework – Project State

Last updated: 2026-08-06

## Project goal

Build a reusable Wazuh security monitoring framework that can later be deployed in a larger production environment.

The Git repository is the authoritative source of configuration and project state.

## Document roles

- `PROJECT-STATE.md` - authoritative record of implemented and tested state and the immediate next work.
- `docs/roadmap.md` - planned progression and release milestones.
- `modules/<module>/README.md` - module scope, design and completion criteria.
- Module matrices - detailed event/rule/test/notification mapping.

If documents disagree about implementation status, `PROJECT-STATE.md` must be corrected from real production evidence before further development continues.

## Working model

MASTER repository:

`/opt/wazuh-security-framework`

Production Wazuh configuration:

`/var/ossec/etc`

Workflow:

1. Edit files in `/opt/wazuh-security-framework`.
2. Validate configuration.
3. Deploy using `wsf deploy`.
4. Test the real event in Wazuh.
5. Save confirmed changes using `wsf save "description"`.

Do not develop configuration directly in `/var/ossec/etc`.

---

# Current modules

## Firewall / Shorewall

Files:

- `rules/1005-pco-firewall_rules.xml`
- `decoders/1005-pco-shorewall_decoder.xml`

Status: implemented and imported from the current production Wazuh configuration. Further policy/testing consolidation remains a later roadmap item.

---

## Rspamd

Files:

- `rules/pco-rspamd_rules.xml`
- `decoders/pco-rspamd_decoders.xml`

Status: implemented and imported from the current production Wazuh configuration.

---

# Windows Authentication v0.2.0

Primary files:

- `rules/1010-windows-authentication_rules.xml`
- `rules/1011-windows-kerberos-4771.xml`
- `rules/1012-windows-account-lockout.xml`
- `modules/windows-authentication/README.md`
- `modules/windows-authentication/authentication-matrix.md`

Status: COMPLETE as of 2026-07-27. Event-analysis baseline, target-manager validation, Windows Authentication Security dashboard and final production notification-policy review are complete for the defined v0.2.0 scope.

## Authentication baseline

| Event ID | Meaning | Wazuh/custom coverage | Status | Email policy |
|---:|---|---|---|---|
| 4624 | Successful logon | stock 60106 | TESTED | No |
| 4625 | Failed logon | stock 60105/60122; custom 101000, 101001, 101002 | TESTED for implemented classifications/correlation | No for 101000/101001/101002 |
| 4634 | User logoff | stock 60137 identified | INTENTIONALLY EXCLUDED from v0.2.0 detection baseline | No |
| 4648 | Explicit credentials used | no stock alerting coverage found on server07; no generic custom rule approved | TESTED for Windows behavior / no generic Wazuh alert | No generic email |
| 4672 | Special privileges assigned | stock 67028, level 3 | TESTED on real event and target manager | No generic email; enrichment/correlation |
| 4740 | Account locked out | custom 101200 based on stock 60115 | TESTED | Yes - 101200 |
| 4771 | Kerberos pre-authentication failed | custom 101100/101101/101102/101110 | TESTED for implemented scenarios | Only 101110 repeated attack correlation |
| 4776 | NTLM credential validation | observed during controlled NTLM failures; no custom rule approved | OBSERVED / TELEMETRY | No generic email |

### Final authentication notification policy

Production rule review on `server07` confirmed:

- 101000 - no email;
- 101001 - no email;
- 101002 - no email;
- 101101 - no email;
- 101102 - no email;
- 101110 - email enabled with `alert_by_email`;
- 101200 - email enabled with `alert_by_email`.

---

# Windows User Management

File:

`rules/1020-windows-user-management.xml`

| Wazuh rule | Windows Event ID | Meaning | Status |
|---|---:|---|---|
| 102000 | 4720 | User account created | TESTED |
| 102001 | 4722 | User account enabled | TESTED |
| 102004 | 4725 | User account disabled | TESTED |
| 102005 | 4726 | User account deleted | TESTED |
| 102006 | 4738 | User account changed | TESTED |

These management rules generate email alerts according to their configured policy.

---

# Windows Password Management

File:

`rules/1021-windows-password-management.xml`

| Wazuh rule | Windows Event ID | Meaning | Status |
|---|---:|---|---|
| 102100 | 4724 | Administrator reset user password | TESTED |
| 102101 | 4723 | User changed own password | TESTED |

Confirmed behavior:

- 4724 / 102100: administrator password reset, email enabled.
- 4723 / 102101: normal user changes own password, email disabled.

---

# Windows Group Membership

Tested stock Wazuh rules:

| Windows Event ID | Wazuh rule | Meaning | Status |
|---:|---:|---|---|
| 4728 | 60141 | Global security group member added | TESTED - STOCK |
| 4729 | 60142 | Global security group member removed | TESTED - STOCK |
| 4732 | 60144 | Local security group member added | TESTED - STOCK |
| 4733 | 60145 | Local security group member removed | TESTED - STOCK |
| 4756 | 60151 | Universal security group member added | TESTED - STOCK |
| 4757 | 60152 | Universal security group member removed | TESTED - STOCK |

No custom rules are required for ordinary group-membership events.

---

# Windows Privileged Group Management

File:

`rules/1022-windows-privileged-groups.xml`

Policy:

**Adding a member to a monitored privileged group generates a level 12 alert and immediate email notification.**

Removing a member remains handled by the stock Wazuh rules unless a future documented requirement changes that policy.

Custom rules:

| Wazuh rule | Group | Event | Status |
|---|---|---:|---|
| 102200 | Account Operators | 4732 | TESTED |
| 102201 | Server Operators | 4732 | TESTED |
| 102202 | Print Operators | 4732 | IMPLEMENTED — separate laboratory test not planned |
| 102203 | Replicator | 4732 | IMPLEMENTED — separate laboratory test not planned |
| 102204 | Key Admins | 4728 | TESTED |
| 102205 | Enterprise Key Admins | 4756 | TESTED |
| 102206 | Organization Management | 4756 | TESTED |
| 102207 | Exchange Trusted Subsystem | 4756 | TESTED |

Rules `102202` and `102203` use the same validated rule structure and stock parent behavior as the other tested privileged-group rules. Only the monitored group identifiers differ. Separate tests were explicitly rejected because they would repeat an already validated mechanism without adding new technical evidence.

---

# Windows Privilege Escalation

Primary files:

- `rules/1110-windows-privilege-escalation.xml`
- `modules/windows-privilege-escalation/privilege-escalation-matrix.md`
- `docs/windows-privilege-escalation/`

Status: COMPLETE for the approved event baseline. Event 4703 remains explicitly deferred and does not block module completion.

| Event ID | Meaning | Coverage | Status | Email policy |
|---:|---|---|---|---|
| 4672 | Special privileges assigned to a new logon | stock 67028 | TESTED AS TELEMETRY | No |
| 4673 | A privileged service was called | stock 60107 for failures; successful events retained as telemetry | ANALYZED – NO GENERIC CUSTOM RULE | No |
| 4674 | Operation attempted on a privileged object | telemetry only | ANALYZED – NO GENERIC CUSTOM RULE | No |
| 4688 | A new process was created | stock 67027 | TESTED AS TELEMETRY | No |
| 4697 | A service was installed in the system | custom 111000, level 10 | TESTED – CUSTOM RULE | No generic email |
| 7045 | A service was installed in the system | stock 61138, level 5 | TESTED – STOCK RULE | No duplicate email |
| 4964 | Special groups assigned to a new logon | custom 111201, level 10 | TESTED – CUSTOM RULE | No |
| 1102 | Security audit log was cleared | custom 111400, level 12 | TESTED – CUSTOM RULE | Yes |
| 4698 | Scheduled task was created | stock 60228, level 4 | TESTED AS TELEMETRY | No |
| 4703 | A token right was adjusted | no live sample; no stock rule | DEFERRED | No |
| 4719 | System audit policy was changed | stock 60112, level 8 | TESTED – STOCK RULE | No generic email |

Validated custom rules:

- `111000` - Event 4697 service installation, level 10.
- `111200` - internal Event 4964 base rule, level 0.
- `111201` - Event 4964 human-account special-group logon, level 10.
- `111400` - Event 1102 Security audit log cleared, level 12, immediate email.

Important decisions:

- do not alert generically on common process names from Event 4688;
- do not create portable generic success rules for Event 4673 or Event 4674;
- do not duplicate adequate stock rules;
- Event 4703 remains deferred until a real production sample is available;
- Event 4698 remains stock telemetry; persistence-specific child rules require a separately approved work item.

---

# Current work

## Active milestone: NTLM Monitoring v0.4.0

The Windows Privilege Escalation module is closed for its approved scope. The next approved module is NTLM Monitoring.

Initial NTLM work must begin with documentation and evidence collection, not custom rules:

1. define the module scope and completion criteria;
2. inventory relevant Windows NTLM event sources and active stock Wazuh coverage;
3. inspect existing real Event 4776 and related authentication data;
4. classify observed NTLM scenarios before approving custom detections;
5. define notification policy only after measured validation.

No new NTLM rule is approved yet.

---

# Important project rule

Do not expand the scope while working on the current module.

Do not add new features just because they might be useful.

Finish and test the current planned item before moving to another area.

`PROJECT-STATE.md` is the reference for determining what is already completed and what should be done next.
