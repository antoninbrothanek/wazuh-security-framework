# Wazuh Security Framework

> Production-ready monitoring. Low noise. High value.

## Overview

Wazuh Security Framework is an open-source project focused on building a reusable security monitoring framework for enterprise environments.

The framework is designed for long-term operation in production and follows one simple principle:

> Every rule must have a clear purpose, documentation, testing and operational value.

## Project Goals

- Build reusable security monitoring modules.
- Prefer standard Wazuh rules whenever possible.
- Create custom rules only when standard rules are insufficient.
- Keep false positives to a minimum.
- Include dashboards and alerting for every module.
- Maintain complete documentation and testing.
- Make every module portable to another Wazuh installation.
- Prove telemetry coverage before drawing conclusions from missing findings.
- Separate evidence collection, posture assessment and hardening from enforcement.

## Security Posture + Monitoring

WSF is evolving from pure event detection into an evidence-driven **Security Posture + Monitoring** framework.

The intended operating cycle is:

`measure -> understand -> define target state -> pilot hardening -> verify -> enforce`

WSF can define and validate telemetry prerequisites and produce deployment plans for Group Policy, but hardening and policy linking remain explicitly controlled administrative actions. The framework must not assume that an absence of alerts means an absence of activity unless the required Windows event sources are demonstrably enabled and collected by Wazuh.

## Windows audit telemetry provisioning

The repository contains a portable Domain Controller telemetry definition under:

- `policies/windows/domain-controller-audit.xml`

The policy describes the Windows audit telemetry required by the framework without embedding customer-specific domains, SIDs, hostnames or OU paths. Domain-specific privileged-group SIDs are resolved at runtime.

Provisioning is intentionally staged:

1. `scripts/windows/create_wazuh_audit.ps1` validates the XML, resolves AD context and SIDs, and prints a read-only provisioning plan.
2. `scripts/windows/create_wazuh_audit_gpo.ps1` can create a new **empty, unlinked GPO** after validation.
3. Audit settings, security options, registry preferences and event-channel configuration are verified separately before any linking or wider deployment.
4. GPO linking is an explicit administrator action and is never performed automatically by the current provisioning scripts.

The planner and safe GPO-creation stage have been validated against a real Active Directory forest, including PowerShell 7 environments where the ActiveDirectory and GroupPolicy modules are loaded through `WinPSCompatSession`.

## Modules

- Windows Authentication
- Windows Privilege Escalation
- Kerberos
- NTLM
- Active Directory
- Microsoft Exchange
- Linux Firewall

Current Windows Privilege Escalation documentation:

- `modules/windows-privilege-escalation/README.md`
- `modules/windows-privilege-escalation/privilege-escalation-matrix.md`
- `docs/windows-privilege-escalation/event-4697-service-installed.md`

## Version

Current development version:

**v0.1.0 – Foundation**
