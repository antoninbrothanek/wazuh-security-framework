# Decision Log

This document records important architectural and technical decisions.

## Template
- Date
- Module
- Decision
- Reason
- Alternatives
- Evidence
- Result

## Entries

### 2026-07-30
**Module:** Windows Privilege Escalation

**Decision:** Do not create a generic detection rule for Event ID 4673.

**Reason:** Initial testing showed legitimate LSASS activity repeatedly generates Event ID 4673 with SeTcbPrivilege.

**Evidence:** Laboratory testing on Windows Server 2019.

**Result:** Accepted.
