# Wazuh Security Framework – Project State

Last updated: 2026-07-24

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

Status: IN DEVELOPMENT. Several detections are implemented and tested, but the complete v0.2.0 baseline is not yet closed.

## Authentication baseline

| Event ID | Meaning | Wazuh/custom coverage | Status | Email policy |
|---:|---|---|---|---|
| 4624 | Successful logon | stock 60106 identified | REVIEW / TEST REQUIRED | ordinary logon: No |
| 4625 | Failed logon | stock 60105/60122 plus custom 101000/101001 | PARTIALLY TESTED | correlation/high-risk only |
| 4634 | User logoff | stock 60137 identified | TEST REQUIRED | No |
| 4648 | Explicit credentials used | stock coverage not found during initial analysis | ANALYSIS REQUIRED | selected high-risk cases only |
| 4672 | Special privileges assigned | stock 67028 identified in WEF baseline | TARGET VALIDATION REQUIRED | selected cases only |
| 4740 | Account locked out | custom 101200 based on stock 60115 | TESTED | Yes |
| 4771 | Kerberos pre-authentication failed | custom 101100/101101/101102/101110 | TESTED for implemented scenarios | correlated attack: Yes |

### Implemented authentication rules

`rules/1010-windows-authentication_rules.xml`

- 101000 - Event 4625 incorrect-password classification.
- 101001 - repeated incorrect password for the same account and source IP.

`rules/1011-windows-kerberos-4771.xml`

- 101100 - internal Event 4771 base rule.
- 101101 - status 0x18, invalid password/stale credentials.
- 101102 - status 0x12, locked/disabled/revoked account scenario.
- 101110 - repeated invalid-password correlation; email enabled.

`rules/1012-windows-account-lockout.xml`

- 101200 - Event 4740 authoritative account-lockout alert; tested with real production event; email enabled.

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

## Active milestone: Windows Authentication v0.2.0

Privileged Group Management implementation is complete for the planned custom-rule set; two individual rule tests remain documented as pending and can be completed without expanding its scope.

The next development work is to close the Windows Authentication v0.2.0 baseline in this order:

1. Event 4624 - validate successful-logon stock behavior and define which scenarios, if any, require higher-severity detection.
2. Event 4625 - complete failed-logon failure-reason analysis beyond the current incorrect-password case.
3. Event 4634 - validate stock logoff behavior; no routine email.
4. Event 4648 - analyze explicit-credential usage and stock Wazuh coverage before deciding on a custom rule.
5. Event 4672 - verify real event behavior and confirm standard rule 67028 is loaded and suitable.
6. Synchronize `authentication-matrix.md` with the verified results.
7. Implement and validate the Windows Authentication dashboard.
8. Review the notification policy and documentation.
9. Mark Windows Authentication v0.2.0 complete only after all completion criteria are satisfied.

Before adding another rule:

1. Verify the Windows event exists.
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
