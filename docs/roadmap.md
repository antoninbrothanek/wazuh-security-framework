# Wazuh Security Framework Roadmap

Last reviewed: 2026-07-24

## Status model

- `[x]` completed and verified
- `[~]` partially implemented or verification still required
- `[ ]` planned

The roadmap describes planned project progression. `PROJECT-STATE.md` remains the authoritative record of what has actually been implemented and tested.

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
- [~] Event ID analysis
- [~] Detection rules
- [~] Email notification policy
- [~] Test scenarios
- [~] Documentation
- [ ] Windows Authentication dashboard

Authentication baseline status:

- [ ] 4624 - Successful logon: validate stock detection and define security use cases
- [~] 4625 - Failed logon: stock detection validated; incorrect-password classification and correlation implemented; remaining failure classifications to review
- [ ] 4634 - Logoff: validate stock detection; no email expected
- [ ] 4648 - Explicit credentials: analyze event and stock Wazuh coverage; custom rule only if required
- [ ] 4672 - Special privileges assigned: validate event and standard rule 67028 on target Wazuh
- [x] 4740 - Account lockout: custom notification rule 101200 tested; email enabled

Completion criteria for v0.2.0:

1. All baseline events above are classified as stock, custom, or intentionally ignored.
2. Every custom rule has a real-event test.
3. Email policy is documented for each security scenario.
4. Authentication matrix and module README match production behavior.
5. Windows Authentication dashboard is implemented and validated.

---

## v0.3.0 Kerberos

Current implementation exists ahead of this roadmap milestone and will be consolidated here.

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

- [ ] NTLM monitoring scope
- [ ] Event analysis
- [ ] Detection rules
- [ ] Notification policy
- [ ] Dashboards
- [ ] Documentation

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
- [~] Privileged Group Management test coverage: six custom rules tested; Print Operators and Replicator remain implemented but not individually tested
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
