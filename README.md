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
