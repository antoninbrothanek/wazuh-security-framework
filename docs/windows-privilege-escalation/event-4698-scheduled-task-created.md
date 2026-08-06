# Event ID 4698 – Scheduled Task Created

## Status

TESTED AS TELEMETRY — STOCK RULE 60228

## Purpose

Event ID 4698 records the creation of a scheduled task in the Windows Security log.

The event is security-relevant because scheduled tasks can be used for persistence or execution, but the event alone does not prove malicious activity.

## Stock Wazuh coverage

The active Wazuh ruleset contains rule `60228` in `0580-win-security_rules.xml`:

- parent rule: `60103`;
- Event ID: `4698`;
- level: `4`;
- description: `A scheduled task was created`;
- MITRE ATT&CK: `T1053`;
- email: disabled.

The stock rule is sufficient as generic telemetry for Event ID 4698.

## Live validation

Live EventChannel ingestion was confirmed on `server07`.

Observed hosts included:

- `TERMINALSERVER`;
- `TERMINAL2`.

Observed legitimate task families included:

- `\Lenovo\Vantage\Schedule\LenovoSystemUpdateAddin_DeferTask`;
- `\OneDrive Per-Machine Standalone Update Task`;
- `\SoftLanding\...\SoftLandingTriggerTask-...`;
- `\SoftLanding\...\SoftLandingDeferralTask-...`.

Observed creators included:

- machine account `PCO\TERMINALSERVER$`;
- normal user accounts on `TERMINAL2`.

The measured environment demonstrates that scheduled-task creation is not rare enough to justify a generic high-severity custom alert.

## Audit-policy observation

`SERVER01` reported:

```text
Other Object Access Events: No Auditing
```

This does not invalidate the live Event 4698 telemetry observed on other systems. Audit-policy state must be verified on the actual host role producing the event before proposing a Group Policy change.

No audit-policy change was approved as part of this validation.

## Framework decision

- retain stock Wazuh rule `60228`;
- do not create a generic custom Event 4698 rule;
- do not enable generic email notification;
- use Event 4698 as telemetry and investigation context;
- any future custom detection must match a specific validated attack pattern, task action, command line, task path or execution context;
- future persistence-specific logic belongs to an explicitly approved Persistence work item and is not part of this baseline decision.

## Final disposition

Telemetry only, using stock rule `60228`.
