# Wazuh Security Framework – Project State

Last updated: 2026-07-27

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

Historical `.bak-*` files are not authoritative; this review used the active `.xml` files in `/var/ossec/etc/rules/`.

### Event 4625 verified state

Real and controlled events confirmed that Event 4625 is received and decoded correctly and that stock rule `60122` produces the expected level 5 generic alert.

Verified/observed failure combinations:

- `0xc000006d / 0xc0000064` - username does not exist; controlled test with `WazuhNoSuchUser`; custom rule 101002 validated on 2026-07-25.
- `0xc000006d / 0xc000006a` - existing account with incorrect password; controlled test with `wazuh4738`; custom rule 101000 validated on 2026-07-25.
- `0xc000006e / 0xc0000071` - expired password; observed in production.
- `0xc000006e / 0xc0000072` - disabled account; observed in production. The inspected sample originated from local Exchange process `MSExchangeMailboxAssistants.exe`, demonstrating that status/subStatus alone must not imply an attack.
- `0xc000035b / 0x0` - observed NTLM/SSPI failure class; requires context and is not automatically classified as malicious.

Controlled testing on 2026-07-25 established the following:

- custom child rules based on stock rule `60122` are loaded and evaluated correctly;
- 101000 matched a real Event 4625 with status `0xc000006d` and subStatus `0xc000006a`;
- the alert description correctly included username `wazuh4738` and source IP `192.168.150.140`;
- 101001 matched after three 101000 events within 300 seconds for the same username and source IP;
- 101001 produced the expected level 8 correlation alert;
- Event 4740 generated by the lockout sequence matched existing rule 101200;
- a controlled `WazuhNoSuchUser` attempt generated Event 4625 with status `0xc000006d`, subStatus `0xc0000064`, NTLM, Logon Type 3, workstation `TERMINAL2`, source IP `192.168.150.140`;
- the same event matched custom rule 101002 at level 5 with the expected username and source IP in the description;
- Event 4776 was observed in parallel with NTLM failures, including statuses `0xc000006a`, `0xc0000064` and `0xc0000234`; no 4776 custom rule was added.

The earlier 101000/101002 matching issue was caused by unnecessary field-presence conditions using `.+`. After removing those conditions, the intended status/subStatus classifications matched correctly. Temporary diagnostic rule 101099 was removed after testing.

### Event 4648 verified state

Controlled testing on `TERMINAL2` confirmed that Event 4648 provides distinct explicit-credential context.

Observed controlled examples included:

- `SubjectUser=kerberos01`, `TargetUser=administrator`, `TargetServer=localhost` during explicit local credential use;
- `SubjectUser=kerberos01`, `TargetUser=administrator`, `TargetServer=server01`, `IpAddress=192.168.150.2`, `IpPort=445` during SMB access using explicit credentials;
- legitimate UAC/elevation activity using `consent.exe`, showing that 4648 alone must not be classified as malicious.

Target-manager validation on `server07` established:

- no controlled Event 4648 alert was present in `wazuh-alerts-*`;
- no loaded stock/custom rule explicitly matches Windows Event ID 4648;
- the only grep hit for text `4648` was unrelated FortiMail rule ID `44648`;
- `wazuh-archives-*` is not indexed on this manager, so archive-index confirmation is unavailable.

Decision: retain 4648 as security-relevant telemetry for documented high-risk conditions/correlation. Do not create a generic alert solely because stock alerting coverage is absent. No generic custom 4648 rule is approved in v0.2.0.

### Event 4672 verified state

Controlled testing on `TERMINAL2` with `PCO\administrator` generated Event 4672 with sensitive privileges including `SeSecurityPrivilege`, `SeTakeOwnershipPrivilege`, `SeBackupPrivilege`, `SeRestorePrivilege`, `SeDebugPrivilege` and `SeImpersonatePrivilege`.

The Event 4672 `SubjectLogonId=0x364a5812` matched Event 4624 `TargetLogonId=0x364a5812` for the same administrator logon.

Target-manager validation on `server07` confirmed stock rule `67028` in `0955-WEF-baseline_rules.xml`:

- matches Event ID 4672;
- level 3;
- excludes LocalSystem SID `S-1-5-18`;
- description `Special privileges assigned to new logon.`

A real `TERMINAL2` Event 4672 for `PCO\administrator` matched rule `67028` at level 3. A second legitimate event from `server02` for machine account `SERVER01$` also matched rule `67028`, confirming that this event is normal privileged-logon telemetry and should not be treated as a generic incident.

Decision: 4672 is correlation/enrichment for a privileged logon rather than a generic standalone alert. Stock rule 67028 is loaded and suitable on the validated target manager. No custom rule and no generic email are required.

### Event 4634 disposition

A controlled session-close check did not produce a useful 4634 event for the tested session. Because no current security detection requirement depends on logoff, further 4634 testing is intentionally deferred and the event is excluded from the v0.2.0 detection baseline.

### Implemented authentication rules

`rules/1010-windows-authentication_rules.xml`

- 101000 - Event 4625 incorrect-password classification; TESTED; no email.
- 101001 - repeated incorrect-password correlation for the same account and source IP; TESTED; no email.
- 101002 - Event 4625 nonexistent-username classification; TESTED; no email.

`rules/1011-windows-kerberos-4771.xml`

- 101100 - internal Event 4771 base rule.
- 101101 - status 0x18, invalid password/stale credentials; no email.
- 101102 - status 0x12, locked/disabled/revoked account scenario; no email.
- 101110 - repeated invalid-password correlation; email enabled.

`rules/1012-windows-account-lockout.xml`

- 101200 - Event 4740 authoritative account-lockout alert; tested with real production and controlled events; email enabled.

### Windows Authentication Security dashboard

Dashboard implementation and validation completed on 2026-07-27.

The dashboard contains:

- failed-logon count for Event 4625;
- repeated failed-logon count using rule 101001;
- unknown-username count using rule 101002;
- account-lockout count using rule 101200;
- top failed usernames;
- top failed source IP addresses;
- authentication-failure timeline;
- Kerberos failure split metrics for rules 101101, 101102 and 101110;
- top privileged user accounts using stock rule 67028.

For the privileged-user visualization, machine accounts and `SYSTEM` are excluded from the Terms bucket using the validated expression `(.*\$|SYSTEM)`. This prevents normal machine-account 4672 volume from dominating the security view while retaining the underlying stock rule as the data source.

Detailed panel/filter definitions are documented in `modules/windows-authentication/README.md`.

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
|---|---:|---|---|
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
| 102202 | Print Operators | 4732 | IMPLEMENTED - individual test pending |
| 102203 | Replicator | 4732 | IMPLEMENTED - individual test pending |
| 102204 | Key Admins | 4728 | TESTED |
| 102205 | Enterprise Key Admins | 4756 | TESTED |
| 102206 | Organization Management | 4756 | TESTED |
| 102207 | Exchange Trusted Subsystem | 4756 | TESTED |

Confirmed custom-alert properties:

- level 12
- `mail: true`
- member identity included
- administrator performing the change included

Stock Wazuh rules are retained where they already provide sufficient level 12 detection, including:

- Administrators
- Domain Admins
- Domain Controllers
- Schema Admins
- Enterprise Admins
- Backup Operators

No duplicate custom rules are created for these groups.

---

# Current work

## Completed milestone: Windows Authentication v0.2.0

Windows Authentication v0.2.0 was completed on 2026-07-27 for the defined scope:

- authentication baseline events have explicit dispositions;
- custom 4625 and Kerberos rules were validated with controlled real events;
- account lockout rule 101200 was validated;
- 4648 and 4672 were analyzed and given explicit stock/custom-policy decisions;
- target-manager behavior was validated on `server07`;
- Windows Authentication Security dashboard was implemented and validated;
- production notification policy was reviewed against active XML rules;
- authentication email is explicitly enabled only for 101110 and 101200.

No further Windows Authentication work is required for v0.2.0. Future changes require a new documented requirement or a later module/release scope.

Before adding another rule anywhere in the framework:

1. Verify the source event exists in the authoritative source log.
2. Verify Wazuh receives the event.
3. Check existing stock Wazuh rules.
4. Add only the required custom rule.
5. Test it with a real event.
6. Mark it TESTED only after confirmation.

---

# Important project rule

Do not expand the scope while working on the current module.

Do not add new features just because they might be useful.

Finish and test the current planned item before moving to another area.

`PROJECT-STATE.md` is the reference for determining what is already completed and what should be done next.
