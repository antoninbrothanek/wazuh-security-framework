# Development Principles

Version: 1.0
Status: Active

## Primary Objective
The primary objective of this project is correctness, reproducibility and educational value — not the number of implemented detection rules.

## 1. Source of Truth
The GitHub repository is the official documentation of the project. The production environment is the authoritative implementation. Every committed change must correspond to a verified implementation.

## 2. Development Workflow
1. Implement.
2. Test on a real system.
3. Verify Windows events.
4. Verify Wazuh ingestion.
5. Verify decoder.
6. Verify stock rules.
7. Create a custom rule only if necessary.
8. Validate.
9. Deploy.
10. Commit.

## 3. Evidence-Based Development
Nothing is considered true until verified by Microsoft documentation, Wazuh documentation, source code, or laboratory testing. Otherwise mark it as **HYPOTHESIS**.

## 4. Scope Control
Only implement work defined in PROJECT-STATE.md and roadmap.md.

## 5. Minimal Changes
Implement the smallest necessary change. Avoid speculative improvements.

## 6. Custom Rules
Verify Windows event, decoder and stock rules before creating a custom rule.

## 7. Testing
Every detection must be reproducible and documented.

## 8. Documentation
Document what, how and why something was implemented, including limitations.

## 9. No Assumptions
If uncertain, state the uncertainty, verify it, then document the result.

## 10. Quality over Speed
Correctness is always more important than speed.
