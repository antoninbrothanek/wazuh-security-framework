# Wazuh Security Framework – Project Rationale

## Why this project exists

The Wazuh Security Framework (WSF) exists to solve a practical infrastructure-security problem: administrators are responsible not only for detecting attacks, but also for understanding how systems are configured, where legacy security dependencies remain, and whether approved hardening changes actually improve the environment without breaking production.

WSF is therefore not an AI experiment, a collection of interesting rules, or an attempt to maximize the number of alerts. It is an operational security framework intended to support real administrative responsibility.

The central question is not:

> What can Wazuh detect?

The central questions are:

> What security state should the environment be in?
>
> What evidence shows the current state?
>
> What should be changed?
>
> How do we verify that the change worked and did not create an undocumented outage?

## Operational motivation

Infrastructure administrators routinely work across domains that overlap operational reliability and security:

- Active Directory;
- Windows authentication;
- Microsoft Exchange;
- Windows and Linux servers;
- privileged access;
- legacy protocols;
- Group Policy;
- audit configuration;
- identity and authentication dependencies.

Security problems often appear first as operational anomalies, while operational problems can reveal weak security posture. WSF is intended to help an administrator work with both sides of that reality without requiring manual review of an unmanageable volume of logs.

The framework must therefore prioritize useful evidence over alert volume.

## Reference standards

WSF should not invent its own hardening standard when authoritative baselines already exist.

For Microsoft environments, the intended reference model is:

1. **Microsoft Security Baselines** – the primary vendor-recommended target configuration for supported Windows platforms.
2. **CIS Benchmarks** – an independent and auditable hardening benchmark used to measure configuration posture.
3. **Wazuh Security Configuration Assessment (SCA)** – continuous configuration assessment and compliance monitoring against supported or project-approved policies.
4. **Wazuh event telemetry and custom rules** – behavioral evidence showing whether authentication, privilege, and security controls behave as expected in real operation.

Microsoft baseline and CIS benchmark controls are related, but they are not treated as interchangeable. Where they differ, WSF should document the chosen target and the reason for that choice.

## WSF operating model

WSF follows this cycle:

`measure -> understand -> define target state -> pilot hardening -> verify -> enforce`

### Measure

Collect sufficient telemetry to understand the current state. Use raw event data when alert indices are insufficient.

### Understand

Distinguish security incidents from legitimate operational dependencies, configuration drift, legacy behavior, application requirements, and expected infrastructure traffic.

### Define target state

Use authoritative guidance such as Microsoft Security Baselines and CIS Benchmarks to define the desired configuration. Do not create arbitrary security requirements solely because a setting appears stricter.

### Pilot hardening

Apply restrictive changes in a controlled scope first. Group Policy and operating-system enforcement remain explicitly approved administrative actions outside Wazuh.

### Verify

Use Wazuh SCA and event telemetry to confirm both configuration compliance and real behavioral effect.

### Enforce

Expand a validated control only after its operational dependencies and exceptions are understood and documented.

## Detection, posture and hardening are separate concerns

WSF deliberately separates three functions.

### Detection

Detection answers questions such as:

- Did a privileged group change?
- Was the Security audit log cleared?
- Is the same account repeatedly failing authentication from the same source?
- Did an authenticated NTLMv1 network logon occur?

Detection rules should remain low-noise and operationally actionable.

### Security posture and compliance

Posture assessment answers questions such as:

- Is the configured authentication policy compliant with the intended baseline?
- Is NTLM auditing enabled?
- Is LM or NTLMv1 still permitted?
- Which systems and accounts still depend on NTLMv2?
- Is a hardening control configured consistently across the domain?

These questions belong primarily to Wazuh SCA, reporting, dashboards, and baseline comparison rather than incident alerting.

### Hardening

Hardening changes the environment. Examples include Group Policy, authentication restrictions, protocol removal, cryptographic policy, or security-option changes.

WSF can recommend and verify hardening, but must not silently enforce it.

## NTLM as the current reference implementation

The NTLM v0.4.0 milestone demonstrates the intended WSF method.

The project first established behavioral evidence:

- authenticated NTLMv1 network logon detection;
- NTLM credential-validation failure classification;
- repeated invalid-password correlation;
- NTLMv2 usage and dependency reporting;
- Event 4776 success baselining;
- separation of authenticated and anonymous NTLM telemetry.

The next step is not immediate NTLM blocking. The project should compare the observed state with Microsoft and CIS guidance, enable audit-only controls where appropriate, measure dependencies, and only then pilot restrictive policy.

The target direction is:

- Kerberos preferred;
- LM eliminated;
- NTLMv1 eliminated;
- NTLMv2 limited to documented dependencies that cannot yet be removed;
- restrictive controls introduced only after evidence-based compatibility assessment.

## Compliance monitoring direction

WSF should use Wazuh SCA as the primary continuous compliance mechanism where suitable policies exist.

The intended model is:

`authoritative baseline -> approved target configuration -> Wazuh SCA -> PASS / FAIL / drift -> remediation decision -> verification`

For Microsoft Windows, WSF should progressively map relevant Microsoft Security Baseline and CIS Benchmark controls into documented project scope, starting with authentication and identity-related settings rather than attempting to absorb the entire operating-system benchmark at once.

This is important for project control: WSF should grow by defined security domains and milestones, not by indiscriminately importing every possible compliance check.

## Scope control

To prevent the project from becoming unfocused, each milestone must answer four questions before work expands:

1. **Why are we doing this?**
2. **What authoritative security target are we comparing against?**
3. **What evidence will Wazuh collect or assess?**
4. **What condition marks the milestone complete?**

New topics should not interrupt the active milestone unless they reveal a prerequisite, a material security risk, or a design error that affects current work.

The roadmap controls sequencing. `PROJECT-STATE.md` records validated implementation state. This document records the enduring reason and method behind the framework.

## Non-goals

WSF is not intended to:

- create an alert for every Windows security event;
- duplicate adequate stock Wazuh rules without operational value;
- treat every compliance failure as an incident;
- automatically deploy restrictive Group Policy settings;
- hard-code customer-specific hosts, accounts, IP addresses or exceptions into the portable framework;
- replace Microsoft, CIS, or vendor security guidance with AI-generated policy;
- broaden into unrelated security subjects without a defined milestone and completion criteria.

## Definition of success

WSF is successful when an administrator can use it to answer, with evidence:

- What is happening?
- Is it expected?
- Is the configuration compliant with the approved target?
- Which legacy or weak dependencies remain?
- What should be changed next?
- Did the approved change actually improve the security posture?
- Did anything regress afterwards?

That is the reason the framework exists.