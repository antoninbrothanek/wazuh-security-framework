# Production Tuning Notes

This document records lessons learned from real Wazuh deployments. Its purpose is to preserve operational experience before changing detection rules, alert levels, e-mail notifications, or agent configuration.

The notes are observations and tuning candidates, not automatic configuration changes. Each proposed change should be validated against the affected environment before deployment.

## 2026-08-08 — CTU production network

### 1. Agent queue flooding can be caused by legitimate Windows activity

On domain controller `srv2-praha` (agent `001`, `172.16.0.8`) Wazuh reported the following queue states:

- rule `202` — Agent event queue is 90% full
- rule `203` — Agent event queue is full; events may be lost
- rule `204` — Agent event queue is flooded
- rule `205` — Agent event queue is back to normal load

A production investigation showed that queue flooding does not necessarily indicate an attack. A very high rate of legitimate Windows Security events can overload the agent event buffer.

**Tuning principle:** Keep rule `204` as a high-priority operational alert and keep e-mail notification enabled. Loss of telemetry is important even when the root cause is operational rather than malicious.

### 2. Do not globally suppress computer accounts ending in `$`

Initial analysis showed many logon/logoff events associated with computer accounts such as `SRV2-PRAHA$`, `SRV1-PRAHA$`, Exchange servers, and workstations. This initially suggested suppressing accounts whose names end in `$`.

Further analysis showed that these accounts were not the main cause of the observed flooding.

**Tuning principle:** Do not globally exclude `*$` accounts from Windows authentication monitoring. Computer accounts can be security-relevant for Kerberos, computer-account changes, domain membership, lateral movement, and other detections. Suppress them only in narrowly scoped rules where they are proven noise.

### 3. SharePoint authentication storm — `spadmin-w2016`

During a ten-minute diagnostic interval on `srv2-praha`, Windows Security contained approximately:

- `23057` × Event ID `4624` — successful logon
- `23057` × Event ID `4627` — group membership information
- `319` × Event ID `4769` — Kerberos service ticket request
- `186` × Event ID `4768` — Kerberos TGT request
- `173` × Event ID `4672` — special privileges assigned

Analysis of Event ID `4624` showed:

- `21924` logons from account `spadmin-w2016`
- source IP `172.16.0.112` (`SRV-SP`)
- Logon Type `3`
- Logon Process `Kerberos`
- Authentication Package `Kerberos`

This represented roughly 36 successful network logons per second from a single SharePoint server/account during the interval.

On `SRV-SP`, the account `CTU2008\spadmin-w2016` was used by multiple SharePoint components, including:

- SharePoint Timer Service (`SPTimerV4`, `OWSTIMER.EXE`)
- SharePoint Server Search (`OSearch15`, `mssearch.exe`)
- SharePoint Search Host Controller (`SPSearchHostController`)
- AppFabric Caching Service
- SharePoint VSS Writer
- multiple `noderunner.exe` processes
- IIS `w3wp.exe` application pools, including SharePoint and Security Token Service

A restart of `SRV-SP` initially stopped the storm and the Wazuh agent returned to normal. This was not a permanent fix.

#### Repeated occurrence after restart

Later on 2026-08-08 the same pattern returned. During the interval `14:05–14:20`, raw Windows Security logs on `srv2-praha` contained:

- `23057` × Event ID `4634` — logoff
- `23047` × Event ID `4624` — successful logon
- `23047` × Event ID `4627` — group membership information
- `482` × Event ID `4769` — Kerberos service ticket request
- `441` × Event ID `4768` — Kerberos TGT request
- `278` × Event ID `4672` — special privileges assigned
- `245` × Event ID `4964` — special groups assigned to a new logon
- `186` × Event ID `4776` — credential validation
- `101` × Event ID `4648` — explicit credentials

Analysis of Event ID `4624` showed:

- `21899` logons from `spadmin-w2016`
- source IP `172.16.0.112` (`SRV-SP`)
- Logon Type `3`
- Authentication Package `Kerberos`

This accounted for approximately 95% of all successful logons in the interval and represented roughly 24 successful network logons per second.

The Wazuh agent queue timeline was:

- `14:11:27` — rule `202`, queue at 90%
- `14:11:34` — rule `203`, queue full
- `14:11:49` — rule `204`, queue flooded
- `14:18:16` — rule `205`, queue back to normal

The queue moved from 90% to flooded in approximately 21 seconds and required more than six minutes to recover.

**Updated conclusion:** The SharePoint-related authentication storm is reproducible. Restarting `SRV-SP` only interrupts the condition temporarily; it does not remove the root cause. The repeated combination of `SRV-SP`, account `spadmin-w2016`, Logon Type `3`, Kerberos, tens of thousands of `4624/4627/4634` events, and subsequent Wazuh queue flooding provides strong evidence that this application-side behavior is the immediate trigger for the agent overload.

**Operational action:** Investigate `SRV-SP` and identify the exact SharePoint component creating the short-lived authenticated sessions. Do not treat Wazuh tuning as the primary remediation.

**Lesson:** A Wazuh authentication-volume anomaly can reveal an operational problem in an application server. Do not immediately suppress the authentication events. Identify the source host, account, logon type, and authentication protocol first.

**Future tuning candidate:** Consider a correlation/threshold rule for an abnormal rate of successful network logons from one `(account, source IP)` pair. A sudden increase can be useful operational and security telemetry even when every individual Event ID `4624` is legitimate.

### 4. Scheduled AD synchronization account `pumaSync`

At approximately 02:10, the account `pumaSync` generated a burst of Windows Event ID `4738` (`A user account was changed`) against multiple user accounts.

The custom rule `102006` generated level-8 alerts of the form:

`Windows user account changed: <target user> by pumaSync`

The activity was confirmed as legitimate batch synchronization.

**Production decision (2026-08-11):** Retain Event ID `4738` and rule `102006` at level 8, but remove `alert_by_email` from rule `102006`. Event 4738 remains visible in Wazuh without generating one email for every expected synchronized account change.

This is a generic notification-policy change, not a `pumaSync`-specific rule exception. Create/enable/disable/delete account-management notifications remain unchanged.

### 5. Kerberos failure codes need semantic differentiation

A Wazuh rule `60131` (`Windows DC Logon Failure`, level 5) matched Windows Event ID `4769` from client `172.17.10.19` with failure/status code `0x20`.

The event occurred only once during the investigated interval.

This demonstrates that a generic `Windows DC Logon Failure` classification is insufficient for triage. Different Kerberos result codes have very different security significance.

**Future tuning candidate:** Create child/custom rules that classify Kerberos failures by Event ID and failure code rather than treating all failures equally. For example, distinguish credential/pre-authentication failures from ticket-lifecycle or transient protocol errors, and use frequency/correlation where appropriate.

A single low-risk Kerberos protocol failure should not have the same operational priority as repeated credential failures from the same account/source.

### 6. Alert index is not raw telemetry

During the queue-flood investigation, the Wazuh alert index contained only a small number of alerts in a period where the Windows Security log contained tens of thousands of raw events.

**Lesson:** `wazuh-alerts-*` represents events that reached the alerting stage. It must not be treated as a complete representation of the raw Windows event rate.

For agent-flood investigations, correlate at least:

1. Wazuh rules `202`–`205` and their timestamps;
2. Windows Security raw event counts on the affected endpoint/DC;
3. Event ID distribution;
4. account + source IP + Logon Type;
5. authentication package/protocol;
6. application/service activity on the source system.

This distinction is important when using automated or AI-assisted analysis over Wazuh Indexer data: absence or low volume in `wazuh-alerts-*` does not prove absence or low volume in the original telemetry.

### 7. Event 4964 requires customer-specific service-account baseline

Production data from CTU showed that custom rule `111201` can generate a very high volume of legitimate alerts for privileged service and automation identities. A 24-hour aggregation included thousands of Event ID `4964` alerts for known infrastructure accounts such as `pumaSync` and `vmadmin`.

A portable hard-coded allowlist was rejected. Instead, rule `111201` now uses the customer-specific CDB list:

`etc/lists/wsf-privileged-service-accounts`

The rule continues to exclude LocalSystem and Active Directory computer accounts ending in `$`, and additionally alerts only when `win.eventdata.targetUserName` is not present in the CDB list.

**Production validation (2026-08-11):**

- `pumaSync` was added to the CTU CDB list after its synchronization role was confirmed;
- no new rule `111201` alerts for `pumaSync` were observed after deployment;
- rule `111201` continued to generate level-10 alerts for accounts not present in the list, including `vmadmin` and `chrudimskyja`;
- the exception is scoped only to rule `111201`; it is not a global trusted-account whitelist.

**Tuning principle:** Keep portable detection logic separate from customer-specific identity baselines. Only confirmed service or automation accounts should be added to the list. Human administrative accounts must not be excluded merely because they generate a high event volume.

## General rule-tuning philosophy

Production tuning should optimize signal-to-noise without destroying forensic visibility.

Prefer this order:

1. identify the real source of event volume;
2. determine whether the activity is legitimate, anomalous, or malicious;
3. preserve raw/audit visibility where practical;
4. tune narrowly by event type, account, source, status code, frequency, or known application behavior;
5. reduce e-mail noise separately from event collection where possible;
6. use correlation/threshold rules for repetitive activity instead of generating thousands of equivalent alerts;
7. document every production exception and the reason for it.

Never globally suppress a broad class of authentication events solely because it is noisy in one production incident.
