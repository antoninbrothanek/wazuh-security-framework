# Wazuh Security Framework Architecture

## Purpose

The Wazuh Security Framework is a modular security monitoring framework designed for long-term operation in production environments.

The goal is not to collect as many alerts as possible, but to provide meaningful security information with minimal false positives.

---

## Design Principles

1. Use standard Wazuh decoders and rules whenever possible.
2. Create custom rules only when standard functionality is insufficient.
3. Every custom rule must have a documented purpose.
4. Every rule must have a test scenario.
5. Every module must include dashboards.
6. Every critical event must have a defined notification policy.
7. The framework must be portable to another Wazuh installation.

---

## Module Structure

Each module contains:

- Documentation
- Detection rules
- Decoders (if required)
- Dashboards
- Test scenarios
- Sample events

---

## Development Workflow

1. Analysis
2. Design
3. Implementation
4. Testing
5. Documentation
6. Release

No rule is implemented before its purpose is clearly defined.

---

## Project Philosophy

The framework is intended for infrastructure administrators.

It focuses on:

- Active Directory
- Microsoft Exchange
- Windows Authentication
- Linux Servers
- Firewalls
- Mail Security

The objective is production-ready monitoring with low operational overhead.