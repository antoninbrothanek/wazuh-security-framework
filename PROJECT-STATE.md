# Wazuh Security Framework – Project State

Last updated: 2026-08-14

## Project goal

Build a reusable Wazuh security monitoring framework that can later be deployed in larger production environments.

The Git repository is the authoritative source of configuration and project state.

## Document roles

- `PROJECT-STATE.md` - authoritative record of implemented and tested state and the immediate next work.
- `docs/roadmap.md` - planned progression and release milestones.
- `modules/<module>/README.md` - module scope, design and completion criteria.
- Module matrices - detailed event/rule/test/notification mapping.

If documents disagree about implementation status, `PROJECT-STATE.md` must be corrected from validated evidence before further development continues.

## Working model

MASTER repository:

`/opt/wazuh-security-framework`

Production Wazuh configuration:

`/var/ossec/etc`

General workflow:

1. Edit files in `/opt/wazuh-security-framework`.
2. Validate configuration.
3. Deploy the approved change to `/var/ossec/etc`.
4. Test the real event in Wazuh.
5. Commit only the validated state to GitHub.

Do not develop configuration directly in `/var/ossec/etc`.

Raw-event collection may be enabled temporarily or permanently in a validation environment when alert indices alone are insufficient for event-code inventory or baseline analysis. Raw telemetry is evidence for rule design; it does not by itself justify a new alert rule.

---

# Current modules

## Firewall / Shorewall

Files:

- `rules/1005-pco-firewall_rules.xml`
- `decoders/1005-pco-shorewall_decoder.xml`

Status: implemented and imported from production Wazuh configuration. Further policy/testing consolidation remains a later roadmap item.

---

## Rspamd

Files:

- `rules/pco-rspamd_rules.xml`
- `decoders/pco-rspamd_decoders.xml`

Status: implemented and imported from production Wazuh configuration.

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
| 4648 | Explicit credentials used | no stock alerting coverage found during validation; no generic custom rule approved | TESTED for Windows behavior / no generic Wazuh alert | No generic email |
| 4672 | Special privileges assigned | stock 67028, level 3 | TESTED on real event and target manager | No generic email; enrichment/correlation |
| 4740 | Account locked out | custom 101200 based on stock 60115 | TESTED | Yes - 101200 |
| 4771 | Kerberos pre-authentication failed | custom 101100/101101/101102/101110 | TESTED for implemented scenarios | Only 101110 repeated attack correlation |
| 4776 | NTLM credential validation | observed during controlled NTLM failures; no custom rule approved | OBSERVED / TELEMETRY | No generic email |

### Final authentication notification policy

Production rule review confirmed:

- 101000 - no email;
- 101001 - no email;
- 101002 - no email;
- 101101 - no email;
- 101102 - no email;
- 101110 - email enabled with `alert_by_email`;
- 101200 - email enabled with `alert_by_email`.

Production validation of `101110` confirmed that same-account + same-source correlation behaves as intended on real Event 4771 / status `0x18` traffic. Events for the same account from another source do not contaminate the correlation sequence, and status `0x12` events are classified independently by rule `101102`.

Result: `101110` production validation PASS. No further XML tuning is currently required for this rule.

---

# Windows User Management

File:

`rules/1020-windows-user-management.xml`

| Wazuh rule | Windows Event ID | Meaning | Status | Email policy |
|---|---:|---|---|---|
| 102000 | 4720 | User account created | TESTED | Yes |
| 102001 | 4722 | User account enabled | TESTED | Yes |
| 102004 | 4725 | User account disabled | TESTED | Yes |
| 102005 | 4726 | User account deleted | TESTED | Yes |
| 102006 | 4738 | User account changed | TESTED IN PRODUCTION | No |

Production review removed `alert_by_email` from rule `102006`. Event 4738 and the level-8 custom alert remain available, while expected synchronization or administration batches no longer generate one email per account change.

---

# Windows Password Management

File:

`rules/1021-windows-password-management.xml`

| Wazuh rule | Windows Event ID | Meaning | Status |
|---:|---:|---|---|
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
- `lists/wsf-privileged-service-accounts`
- `modules/windows-privilege-escalation/privilege-escalation-matrix.md`
- `docs/windows-privilege-escalation/`

Status: COMPLETE for the approved event baseline, with production tuning incorporated for Event 4964. Event 4703 remains explicitly deferred and does not block module completion.

| Event ID | Meaning | Coverage | Status | Email policy |
|---:|---|---|---|---|
| 4672 | Special privileges assigned to a new logon | stock 67028 | TESTED AS TELEMETRY | No |
| 4673 | A privileged service was called | stock 60107 for failures; successful events retained as telemetry | ANALYZED – NO GENERIC CUSTOM RULE | No |
| 4674 | Operation attempted on a privileged object | telemetry only | ANALYZED – NO GENERIC CUSTOM RULE | No |
| 4688 | A new process was created | stock 67027 | TESTED AS TELEMETRY | No |
| 4697 | A service was installed in the system | custom 111000, level 10 | TESTED – CUSTOM RULE | No generic email |
| 7045 | A service was installed in the system | stock 61138, level 5 | TESTED – STOCK RULE | No duplicate email |
| 4964 | Special groups assigned to a new logon | custom 111201, level 10 + deployment-specific CDB exclusion | TESTED IN PRODUCTION | No |
| 1102 | Security audit log was cleared | custom 111400, level 12 | TESTED – CUSTOM RULE | Yes |
| 4698 | Scheduled task was created | stock 60228, level 4 | TESTED AS TELEMETRY | No |
| 4703 | A token right was adjusted | no live sample; no stock rule | DEFERRED | No |
| 4719 | System audit policy was changed | stock 60112, level 8 | TESTED – STOCK RULE | No generic email |

Validated custom rules:

- `111000` - Event 4697 service installation, level 10.
- `111200` - internal Event 4964 base rule, level 0.
- `111201` - Event 4964 privileged-logon alert, level 10, excluding LocalSystem, computer accounts, and deployment-approved service/automation accounts from `etc/lists/wsf-privileged-service-accounts`.
- `111400` - Event 1102 Security audit log cleared, level 12, immediate email.

Production validation confirmed that the CDB exclusion mechanism suppresses approved service/automation identities while other human accounts continue to generate the expected level-10 alert. The CDB list is scoped only to rule `111201` and must not be treated as a global trusted-account whitelist.

Important decisions:

- do not alert generically on common process names from Event 4688;
- do not create portable generic success rules for Event 4673 or Event 4674;
- do not duplicate adequate stock rules;
- Event 4703 remains deferred until a real production sample is available;
- Event 4698 remains stock telemetry; persistence-specific child rules require a separately approved work item;
- keep deployment-specific service/automation identities outside portable rule logic and manage them through the dedicated CDB list used only by rule `111201`.

---

# Kerberos v0.3.0

Status: COMPLETE as of 2026-08-14.

The Kerberos milestone extends the completed Windows Authentication baseline with evidence-driven failure classification, correlation and operational visibility.

Validated coverage:

- Event 4771 base detection: implemented;
- status `0x18` (`KDC_ERR_PREAUTH_FAILED`): rule `101101`, level 5, no email;
- status `0x12` (`KDC_ERR_CLIENT_REVOKED`): rule `101102`, level 7, no email;
- repeated status `0x18` for the same account and source: rule `101110`, level 10, email enabled;
- `101110` same-account + same-source correlation: production validated.

## Raw-event assessment principle

Alert indices contain only events that reach an alerting rule and therefore are not sufficient by themselves to inventory all Kerberos failure codes. Raw Windows Event 4771 telemetry was therefore inspected from Wazuh archives to validate the observed failure-code population.

The raw assessment confirmed `0x18` as the dominant naturally occurring Event 4771 failure code during the validation window. No additional Event 4771 failure code accumulated enough validated evidence to justify another portable custom rule.

## Operational versus security semantics

Kerberos failure codes must not be interpreted without account, source, timing and workload context.

Validated design rules:

- a single `0x18` event is useful authentication telemetry but is not, by itself, evidence of an attack;
- repeated rapid `0x18` failures for the same account and source are covered by `101110`;
- periodic `0x18` failures may indicate persistent or stale credentials in an automated workload and are operationally valuable even when they do not satisfy the attack-correlation threshold;
- machine-account and infrastructure authentication can generate recurring Kerberos failures and must be investigated before being suppressed;
- known infrastructure patterns must not be converted into global account exclusions without evidence that the exclusion is safe and portable.

Persistent low-frequency credential failures remain a documented future detection candidate. No generic correlation threshold is approved in v0.3.0.

## Event 4769 assessment

Event 4769 (Kerberos service-ticket request) failures were assessed as useful Kerberos operational/security telemetry, but not as a basis for a generic custom rule in this milestone.

Observed failure statuses included `0x12` and `0x20`. The assessment confirmed that the same Kerberos failure status can occur in materially different infrastructure and application contexts, and that some failure patterns are operational rather than incident-worthy.

Final decision:

- no generic custom Event 4769 failure rule in v0.3.0;
- classify account type, service principal, source, timing and workload before deciding whether a 4769 failure is security-relevant;
- avoid duplicating adequate stock Wazuh failure alerts without a portable detection requirement.

## Kerberos dashboard

The `Kerberos` dashboard was implemented and validated using `wazuh-alerts-*`.

Validated panels:

- `Kerberos - Invalid Passwords` - metric for rule `101101`;
- `Kerberos - Locked or Revoked Client` - metric for rule `101102`;
- `Kerberos - Correlated Attacks` - metric for rule `101110`;
- `Kerberos - Top Failed Accounts` - rule `101101` grouped by `data.win.eventdata.targetUserName`;
- `Kerberos - Top Failure Sources` - rule `101101` grouped by `data.win.eventdata.ipAddress`;
- `Kerberos - Failures Timeline` - rules `101101`, `101102` and `101110` over time;
- `Kerberos - Recent Security Events` - saved-search table showing time, rule ID, rule description, target account and source IP.

The dashboard intentionally retains machine accounts in analytical views because infrastructure authentication failures can be operationally significant. The dashboard is an investigation and situational-awareness tool and does not alter the email-notification policy.

Result: Kerberos dashboard PASS.

---

# Current work

## NTLM Monitoring v0.4.0

Kerberos v0.3.0 is complete. The active milestone is now NTLM Monitoring v0.4.0.

Initial approved work:

1. define the NTLM monitoring scope and completion criteria;
2. inventory relevant Windows event sources, starting with Event 4776;
3. inspect stock Wazuh coverage and raw-event availability;
4. classify real NTLM success/failure patterns before implementing custom rules;
5. define notification policy only after the event semantics and operational noise are understood;
6. build NTLM dashboard and final documentation after detection decisions are validated.

No new NTLM custom rule is approved at milestone start.

---

# Important project rule

Do not expand the scope while working on the current module.

Do not add new features just because they might be useful.

Finish and test the current planned item before moving to another area.

`PROJECT-STATE.md` is the reference for determining what is already completed and what should be done next.
