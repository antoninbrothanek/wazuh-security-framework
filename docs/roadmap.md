# Wazuh Security Framework Roadmap

Last reviewed: 2026-08-31

## Status model

- `[x]` completed and verified
- `[~]` partially implemented or verification still required
- `[ ]` planned

The roadmap describes planned project progression. `PROJECT-STATE.md` remains the authoritative record of what has actually been implemented and tested.

---

## Strategic direction

WSF is expanding from event detection into an evidence-driven **Security Posture + Monitoring** framework.

The intended operating cycle is:

`measure -> understand -> define target state -> pilot hardening -> verify -> enforce`

The framework should use Wazuh telemetry to identify weak or legacy security dependencies, recommend controlled hardening and verify the effect of approved changes. WSF does not directly enforce Group Policy or operating-system security settings.

Authentication hardening is split into separate technical workstreams. NTLM usage and restriction, Kerberos behavior, and Kerberos cryptographic hardening such as RC4 removal and AES migration must be measured and changed independently even when they contribute to the same overall security objective.

---

## Immediate next work

Kerberos v0.3.0 is complete. The active milestone is now:

## v0.4.0 NTLM Monitoring and Hardening Assessment

The milestone begins with evidence collection and deliberately uses audit before enforcement:

1. define NTLM monitoring and posture completion criteria;
2. inventory Event 4776 and related authentication events;
3. inspect stock Wazuh coverage and raw-event availability;
4. classify real NTLM success and failure patterns before creating custom rules;
5. identify systems, accounts, services and applications that still depend on NTLM;
6. determine which telemetry can distinguish NTLMv1 from NTLMv2;
7. establish an NTLM usage baseline before restrictive policy changes;
8. define the target state: Kerberos preferred, zero NTLMv1/LM, NTLMv2 minimized to documented dependencies;
9. design audit-only and pilot Group Policy hardening steps before enforcement;
10. use Wazuh telemetry to validate the effect and detect remaining or unexpected NTLM dependencies;
11. finalize detection rules, notification policy, dashboard and documentation from validated evidence.

No NTLM custom rule or restrictive Group Policy setting is approved solely by this roadmap update.

### Windows audit telemetry provisioning

Portable telemetry provisioning is being added as a prerequisite for evidence-based NTLM and authentication assessment.

- [x] Declarative Domain Controller audit telemetry policy defined in `policies/windows/domain-controller-audit.xml`
- [x] Read-only planner implemented in `scripts/windows/create_wazuh_audit.ps1`
- [x] Runtime resolution of Domain Admins, Enterprise Admins and Schema Admins SIDs validated against real Active Directory
- [x] PowerShell 7 / `WinPSCompatSession` compatibility validated for ActiveDirectory and GroupPolicy modules
- [x] Safe creation of an empty, unlinked GPO implemented in `scripts/windows/create_wazuh_audit_gpo.ps1`
- [x] Empty unlinked GPO creation validated in a real AD environment
- [ ] Implement native GPO writers for Advanced Audit Policy
- [ ] Implement native GPO writers for Security Options / NTLM auditing
- [ ] Implement SpecialGroups registry preference generation
- [ ] Implement Event Channel configuration
- [ ] Generate and compare `Get-GPOReport` output against the declarative XML
- [ ] Pilot-link the completed telemetry GPO only after configuration verification
- [ ] Verify resulting Windows telemetry and Wazuh ingestion after pilot application

Current safety rule: provisioning scripts do not automatically link GPOs. Linking remains an explicit administrator action outside the automated creation stage.

---

## v0.1.0 Foundation

- [x] Git repository
- [x] GitHub repository
- [x] Initial documentation
- [x] Project structure
- [x] Master-to-production deployment workflow (`wsf deploy` / `wsf save`)

---

## v0.2.0 Windows Authentication

Goal: establish a tested baseline for domain-wide Windows authentication monitoring with low alert noise and explicit notification policy.

- [x] Authentication architecture and design principles
- [x] Event ID analysis
- [x] Detection rules for the approved scope
- [x] Email notification policy
- [x] Test scenarios
- [x] Documentation
- [x] Windows Authentication dashboard

Status: COMPLETE.

---

## Windows Privilege Escalation

Goal: validate high-value Windows privilege-escalation and defense-evasion events while avoiding generic high-noise detections.

- [x] 4672 - privileged-logon telemetry
- [x] 4673 - sensitive privilege-use analysis
- [x] 4674 - privileged-object operation analysis
- [x] 4688 - process-creation telemetry
- [x] 4697 and 7045 - service installation
- [x] 4964 - special-group logon detection
- [x] 1102 - Security audit log clearing
- [x] 4698 - scheduled-task creation telemetry
- [~] 4703 - deferred until a real production sample exists
- [x] 4719 - audit-policy change
- [x] Final module-scope and next-milestone selection

Validated custom rules:

- 111000 - service installation;
- 111201 - human-account special-group logon;
- 111400 - Security audit log cleared, immediate email.

Status: COMPLETE for the approved scope.

---

## v0.3.0 Kerberos

Goal: extend the Windows Authentication baseline with evidence-driven Kerberos failure classification, correlation and operationally useful visibility while avoiding generic high-noise rules.

- [x] Event 4771 baseline detection
- [x] 0x18 invalid-password / pre-authentication-failure classification
- [x] 0x12 locked/revoked-client classification
- [x] Repeated invalid-password correlation rule 101110
- [x] Email notification for correlated password attack
- [x] Production validation of same-account + same-source correlation
- [x] Raw-event assessment methodology for additional failure-code inventory
- [x] Additional Kerberos failure-code review completed for the observed validation window
- [x] Persistent low-frequency credential-failure assessment documented; no generic threshold approved
- [x] Event 4769 failure assessment completed; no generic custom rule approved
- [x] Kerberos dashboard
- [x] Final Kerberos documentation review

Final rule-design decisions:

- do not treat every Kerberos failure as a security incident;
- interpret failure codes together with account, source, timing and workload context;
- no generic Event 4769 failure rule without a portable evidence-backed requirement;
- no persistent-credential correlation threshold without sufficient validated evidence.

Status: COMPLETE.

---

## v0.4.0 NTLM

Goal: establish evidence-driven monitoring and hardening assessment of NTLM without treating every NTLM use or failure as an incident and without introducing restrictive policy before dependencies are understood.

### Detection

- [~] NTLM monitoring scope
- [ ] Event 4776 baseline inventory
- [ ] Related event-source and stock-rule review
- [ ] Real success/failure scenario classification
- [ ] Detection-rule decisions
- [ ] Notification policy

### Usage and posture

- [ ] NTLM usage baseline
- [ ] Top systems/workstations using NTLM
- [ ] Top accounts using NTLM
- [ ] Service/application dependency classification
- [ ] NTLMv1 versus NTLMv2 telemetry assessment
- [ ] Documented exceptions/dependencies

### Hardening assessment

- [ ] Define NTLM target state
- [ ] Target zero LM and NTLMv1 use
- [ ] Minimize NTLMv2 to documented dependencies
- [ ] Review relevant audit-only Group Policy controls
- [ ] Pilot restrictive policy only after dependency remediation
- [ ] Verify policy impact and residual NTLM usage with Wazuh

### Visibility and closure

- [ ] NTLM dashboard
- [ ] Documentation
- [ ] Final detection and hardening decision record

Initial evidence work starts with Event 4776 and related NTLM audit telemetry. Existing Windows Authentication testing is baseline evidence, not by itself an approved detection or hardening policy.

Status: ACTIVE MILESTONE.

---

## Future Authentication Hardening

This work follows evidence from the authentication modules and is deliberately separated from NTLM policy.

Planned subjects include:

- Kerberos encryption-type inventory;
- identification of RC4 dependencies;
- AES readiness and migration assessment;
- controlled removal of weak Kerberos encryption where operational evidence supports it;
- post-change verification through Wazuh telemetry.

The target direction is to remove legacy authentication and weak cryptography without introducing undocumented outages or blanket exclusions.

---

## v0.5.0 Linux Firewall and Edge Services

Some components already exist in production and were imported before this roadmap milestone.

- [x] Shorewall decoder and baseline rules imported
- [~] Shorewall detection policy and testing
- [ ] SSH security monitoring consolidation
- [ ] Postfix security monitoring consolidation
- [x] Rspamd decoder and rules imported
- [ ] Dashboards review
- [ ] Documentation review

---

## v0.6.0 Microsoft Exchange

- [ ] Authentication
- [ ] Transport
- [ ] IIS
- [ ] Privileged Exchange administration monitoring review
- [ ] Dashboards
- [ ] Documentation

---

## v0.7.0 Active Directory

Several Active Directory management detections have already been implemented and tested ahead of this milestone.

- [x] User Management baseline: 4720, 4722, 4725, 4726, 4738
- [x] Password Management baseline: 4723, 4724
- [x] Group membership stock-rule validation: 4728, 4729, 4732, 4733, 4756, 4757
- [x] Privileged Group Management policy and custom rules
- [x] Privileged Group Management mechanism validated; separate Print Operators and Replicator tests intentionally not planned
- [ ] GPO Monitoring
- [ ] AD replication monitoring
- [ ] Active Directory dashboards
- [ ] Final Active Directory documentation review

Critical policy already established: adding a member to a monitored privileged group must generate an immediate level 12 email alert.

---

## v1.0.0 Production Release

- [ ] Cross-module dependency validation
- [ ] Final testing
- [ ] Documentation review
- [ ] Dashboard review
- [ ] Notification-policy review
- [ ] Portable deployment validation on another Wazuh installation
- [ ] Release package
