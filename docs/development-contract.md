# Wazuh Security Framework Development Contract

## Purpose

This document defines the binding working rules for developing the Wazuh Security Framework.

Its purpose is to prevent scope drift, speculative implementation, architectural churn and undocumented decisions. GitHub is the source of truth for the project. Chat history and assistant memory are not authoritative.

## Mandatory reading order

Whenever work resumes on this repository, or when the instruction is given to read the repository, the following files must be read before proposing or implementing changes:

1. `docs/development-contract.md`
2. `docs/development-principles.md`
3. `docs/decision-log.md`
4. `PROJECT-STATE.md`, if present
5. the module documentation and active rule file relevant to the current task

No design proposal or code change should be made before this review is complete.

## Rule 1 — Finish the current work item

Do not start another branch of work until the current item is:

- implemented, if implementation was approved;
- validated with real evidence;
- documented;
- committed to GitHub;
- explicitly closed or assigned a clear remaining status.

## Rule 2 — Ideas are not tasks

A new idea must be classified before any implementation:

- `VERIFIED` — supported by documentation or a completed real test;
- `HYPOTHESIS` — plausible but not yet validated;
- `IDEA` — optional future direction;
- `PLANNED` — explicitly approved for implementation.

Only `PLANNED` items may change code or project scope.

## Rule 3 — No scope expansion without approval

While implementing one Event ID, module or rule, do not expand into another event source, subsystem, telemetry source or architectural layer without explicit approval.

Examples of prohibited unapproved expansion include introducing Sysmon, ETW, PowerShell logging, Linux auditd, AI correlation or additional Event IDs while another item is still open.

New directions must be recorded as `IDEA` or `Future improvement` and left unimplemented.

## Rule 4 — Evidence before conclusions

Every technical conclusion must be based on one or more of:

- authoritative vendor documentation;
- active Wazuh stock rules;
- real Windows events;
- live Wazuh ingestion;
- controlled laboratory validation;
- measured production baseline.

Do not present assumptions, likely behavior or remembered facts as verified results.

## Rule 5 — Stock Wazuh coverage first

Before creating a custom rule:

1. search the active stock ruleset;
2. verify whether the event is already covered;
3. confirm the live decoded field names;
4. decide whether stock behavior is sufficient;
5. add only the minimum necessary custom logic.

No custom rule is approved only because an event appears security-relevant.

## Rule 6 — Do not change architecture during implementation

Once an implementation approach is approved, do not replace it with a broader or more elaborate design during the same work item unless testing proves the approved approach invalid and the user explicitly approves a new direction.

A better-looking idea is not sufficient reason to change course.

## Rule 7 — Test results override prior proposals

Do not defend or preserve a proposal that laboratory or production evidence disproves.

If evidence shows a rule is noisy, non-portable, redundant or not reproducibly testable, remove or reject it and document the decision.

## Rule 8 — No premature completion claims

A rule or module may be marked `TESTED` only when the required positive and negative paths have been validated with real events, unless the documentation explicitly defines a narrower tested status.

Permitted intermediate states include:

- `PLANNED`;
- `PARTIALLY TESTED`;
- `TESTED AS TELEMETRY`;
- `ANALYZED — NO GENERIC CUSTOM RULE`;
- `TESTED — STOCK RULE`;
- `TESTED — CUSTOM RULE`.

## Rule 9 — GitHub is the source of truth

The authoritative project state is the current repository content.

Before modifying a file:

1. fetch its current content and SHA;
2. preserve unrelated content;
3. update only the approved scope;
4. commit with a precise message;
5. report the resulting commit SHA.

If a decision is not recorded in GitHub, it is not a binding project decision.

## Rule 10 — Separate facts from recommendations

Responses and documentation must clearly distinguish:

- observed facts;
- verified configuration;
- test results;
- recommendations;
- hypotheses;
- future ideas.

Recommendations must not be written as if already implemented or tested.

## Rule 11 — Prefer deletion over unjustified complexity

If a generic rule requires broad allowlists, customer-specific assumptions or speculative branching to avoid false positives, the default decision is to remove or reject it from the portable framework.

Customer-specific detection may be documented separately when supported by a measured baseline and an explicit requirement.

## Rule 12 — The user controls scope

The user decides whether to:

- continue;
- stop;
- simplify;
- remove a rule;
- postpone an idea;
- change priority.

When the user says to stop scope expansion or return to the core task, do so immediately without arguing for the broader design.

## Rule 13 — Validate live stock behavior before changing audit policy

When an Event ID already appears in live Wazuh data or matches an active stock rule, do not change Group Policy, Advanced Audit Policy or registry-based audit configuration based only on an assumed audit dependency.

Before proposing an audit-policy change:

1. inspect the active stock rule and its parent chain;
2. confirm the event's live provider, channel, decoder and decoded fields;
3. identify which hosts already generate the event;
4. compare the effective audit policy on the relevant host role;
5. use authoritative vendor documentation when the dependency remains unclear.

A missing audit setting on one host does not prove that the event requires that setting universally or that another host role is configured the same way.

## Working checklist

Before proposing or implementing a change, verify:

- [ ] I read this contract.
- [ ] I read the current project state and decision log.
- [ ] I know the single current work item.
- [ ] I have not expanded scope.
- [ ] I know which claims are verified and which are hypotheses.
- [ ] I checked active stock Wazuh coverage.
- [ ] I inspected live stock-rule behavior before proposing audit-policy changes.
- [ ] I have real decoded fields or authoritative documentation.
- [ ] I am changing only approved files.
- [ ] I will not mark the item complete without evidence.

## Enforcement

If a response or implementation conflicts with this contract, the contract takes precedence. The correction is to return to the last approved scope, verify the repository state and continue from documented evidence.
