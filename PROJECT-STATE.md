# Wazuh Security Framework – Project State

Last updated: 2026-07-24

## Project goal

Build a reusable Wazuh security monitoring framework that can later be deployed in a larger production environment.

The Git repository is the authoritative source of configuration and project state.

## Working model

MASTER repository:

/opt/wazuh-security-framework

Production Wazuh configuration:

/var/ossec/etc

Workflow:

1. Edit files in /opt/wazuh-security-framework
2. Validate configuration
3. Deploy using `wsf deploy`
4. Test the real event in Wazuh
5. Save confirmed changes using `wsf save "description"`

Do not develop configuration directly in /var/ossec/etc.

---

# Current modules

## Firewall / Shorewall

Files:

- rules/1005-pco-firewall_rules.xml
- decoders/1005-pco-shorewall_decoder.xml

Status:

Implemented and imported from the current production Wazuh configuration.

---

## Rspamd

Files:

- rules/pco-rspamd_rules.xml
- decoders/pco-rspamd_decoders.xml

Status:

Implemented and imported from the current production Wazuh configuration.

---

## Windows Authentication

File:

- rules/1010-windows-authentication_rules.xml

Status:

Implemented and imported from the current production Wazuh configuration.

---

## Windows Kerberos 4771

File:

- rules/1011-windows-kerberos-4771.xml

Status:

Implemented and imported from the current production Wazuh configuration.

---

## Windows Account Lockout

File:

- rules/1012-windows-account-lockout.xml

Event:

- 4740 – User account locked out

Status:

Implemented and imported from the current production Wazuh configuration.

---

# Windows User Management

File:

rules/1020-windows-user-management.xml

Implemented rules:

| Wazuh rule | Windows Event ID | Meaning | Status |
|---|---:|---|---|
| 102000 | 4720 | User account created | TESTED |
| 102001 | 4722 | User account enabled | TESTED |
| 102004 | 4725 | User account disabled | TESTED |
| 102005 | 4726 | User account deleted | TESTED |
| 102006 | 4738 | User account changed | TESTED |

Rules generate email alerts using:

`<options>alert_by_email</options>`

---

# Windows Password Management

File:

rules/1021-windows-password-management.xml

Implemented rules:

| Wazuh rule | Windows Event ID | Meaning | Status |
|---|---:|---|---|
| 102100 | 4724 | Administrator reset user password | TESTED |

Confirmed production test:

Event 4724 was received from SERVER01 and matched rule 102100.

Example:

Windows user password reset: wazuh4738 by Administrator

Email alerting is enabled.

---

# Current work

Continue Windows account/password management rules.

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

GitHub PROJECT-STATE.md is the reference for determining what is already completed and what should be done next.
