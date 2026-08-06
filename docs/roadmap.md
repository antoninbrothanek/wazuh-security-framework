# Wazuh Security Framework Roadmap

Last reviewed: 2026-08-06

## Status model

- `[x]` completed and verified
- `[~]` partially implemented or verification still required
- `[ ]` planned

The roadmap describes planned project progression. `PROJECT-STATE.md` remains the authoritative record of what has actually been implemented and tested.

---

## Immediate next work

The Windows Privilege Escalation module is complete for its approved event baseline. Event 4703 remains explicitly deferred pending a real production sample and does not block module completion.

The next approved milestone is:

## v0.4.0 NTLM Monitoring

Initial work must begin with scope definition and evidence collection:

1. define the NTLM monitoring scope and completion criteria;
2. inventory relevant Windows event sources;
3. inspect active stock Wazuh coverage;
4. review existing real Event 4776 and related authentication data;
5. classify observed scenarios before creating custom rules;
6. define notification and dashboard requirements only after validation.

No NTLM custom rule is approved yet.

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

Current implementation exists ahead of this roadmap milestone and will be consolidated later.

- [x] Event 4771 baseline detection
- [x] 0x18 invalid-password classification
- [x] 0x12 locked/revoked-account classification
- [x] Repeated invalid-password correlation rule 101110
- [x] Email notification for correlated password attack
- [ ] Review additional Kerberos failure codes and security scenarios
- [ ] Kerberos dashboard
- [ ] Final Kerberos documentation review

---

## v0.4.0 NTLM

- [~] NTLM monitoring scope
- [ ] Event analysis
- [ ] Detection rules
- [ ] Notification policy
- [ ] Dashboards
- [ ] Documentation

Current status: ACTIVE MILESTONE. Scope definition and evidence collection are the first approved work item.

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
