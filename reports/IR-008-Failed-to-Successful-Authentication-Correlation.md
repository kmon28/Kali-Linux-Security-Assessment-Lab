# IR-008 — Cross-Host Authentication Correlation and PowerShell Detection Engineering

**Date:** October 24–25, 2026  
**Environment:** Isolated VirtualBox Active Directory lab, `lab.local`  
**Systems:** DC02 (192.168.56.101), CLIENT01 (192.168.56.102)  
**Account:** `LAB\socuser`  
**Status:** Controlled detection and correlation validated; no real compromise established

## Executive summary

Developed and tested a native Windows PowerShell detection that correlates failed SMB/network logons (**Security Event 4625**) with a subsequent successful network logon (**Security Event 4624**) for the **same account and originating IP**. A controlled test from CLIENT01 produced three bad-password attempts followed by a correct-password SMB authentication to DC02. The revised detector identified **three failures followed by success at 2026-10-25 01:55:44**, for `socuser` from `192.168.56.102`.

This investigation extends IR-006's failure-count threshold into **sequence-based correlation**, with account, source-IP, time-window, and Logon Type checks. All logons were intentionally generated for validation; the alert is **not evidence of account takeover or brute-force activity**.

## Scope and detection logic

- **Collection:** DC02 Windows Security log via `Get-WinEvent`, without Splunk.
- **Failed event:** 4625, network Logon Type 3; extract target account and source IP.
- **Successful event:** 4624, network Logon Type 3; extract target account and source IP.
- **Correlation:** At least **three** failed logons with matching account and IP **within 15 minutes before** a successful logon.
- **Validation lookback:** 12 hours of historical logs to include the lab test; the **15-minute correlation window** remains distinct from the log-retrieval lookback.
- **Result:** `CORRELATION ALERT` for `socuser`, `192.168.56.102`, three failures, success at `2026-10-25 01:55:44`.

### Critical parsing lesson

Windows Event 4624 and 4625 do **not** use identical property positions for every field:

| Field | 4624 successful logon | 4625 failed logon |
|---|---|---|
| Account | `Properties[5]` | `Properties[5]` |
| Logon Type | `Properties[8]` | `Properties[10]` |
| Source IP | `Properties[18]` | `Properties[19]` |

An initial version incorrectly used `Properties[8]` for Logon Type on both event IDs. The script ran without an exception but produced **no alert**, despite 1,072 retrieved Security events. A focused 4625 inspection showed all relevant failures were Type 3, exposing the incorrect property index. The corrected event-specific index restored the alert (later run retrieved 1,086 Security events). This demonstrates why **silent negative results require schema validation**, not merely syntax checks.

## Investigation timeline (local DC02 time)

| Time | Event | Account | Origin | Interpretation |
|---|---|---|---|---|
| Oct 24, 20:39:38 | 4625, Type 3 | socuser | 192.168.56.101 | Separate controlled failure from DC02; **not** part of CLIENT01 correlation |
| Oct 24, 23:07:23 | 4625, Type 3 | socuser | 192.168.56.102 | Earlier CLIENT01 failure; **outside** final 15-minute sequence |
| Oct 25, 01:43:27 | 4625, Type 3 | socuser | 192.168.56.102 | Controlled incorrect password |
| Oct 25, 01:43:58 | 4625, Type 3 | socuser | 192.168.56.102 | Controlled incorrect password |
| Oct 25, 01:44:27 | 4625, Type 3 | socuser | 192.168.56.102 | Controlled incorrect password |
| Oct 25, 01:55:44 | 4624, Type 3 | socuser | 192.168.56.102 | Controlled successful SMB authentication; **correlation matched** |

The three failures occurred within roughly one minute and preceded the successful logon by approximately 11–12 minutes.

## Validation procedure

1. Confirmed DC02 Security Event 4625 from CLIENT01 and differentiated it from a separate DC02-originated failure.
2. Cleared a conflicting Windows SMB connection after **System error 1219**; the conflict was preventing a new credential attempt.
3. Generated three controlled incorrect-password SMB authentication attempts on CLIENT01; observed expected **System error 1326** and DC02 4625 telemetry.
4. Ran a reusable PowerShell threshold detector and observed: `ALERT: 3 failed logons from 192.168.56.102`.
5. Authenticated successfully to `\\192.168.56.101\IPC$` as `LAB\socuser`, and verified DC02 **4624 / Type 3** at **01:55:44**.
6. Built a second detector to correlate failed and successful authentication by account, IP, and time.
7. Added Type 3 filtering, investigated a silent false negative, corrected event-specific property indexes, and confirmed the correlation alert again.

## Evidence

**Verified repository artifact:**

- [Screenshot 53 — Custom failed-login threshold alert](../screenshots/53-IR008-Failed-Login-Detection-Alert.png)

**Additional evidence observed during the lab session:** screenshot 51 (cross-host failed authentication), 52 (successful SMB authentication), and 54 (failed-to-successful correlation). Their final repository filenames/paths have not yet been verified, so links are intentionally withheld rather than risk broken evidence references.

### Alert output (validated)

```text
CORRELATION ALERT
Account: socuser
Source IP: 192.168.56.102
Failures: 3
Success: 10/25/2026 01:55:44
```

## Detection engineering and limitations

- The current detector is a **batch proof of concept**, not a scheduled production alert or SIEM rule.
- It demonstrates **account/IP/time correlation**, not confirmed credential guessing by an adversary.
- Legitimate mistyped passwords, service misconfiguration, cached connections, and automated retries may generate similar patterns.
- A five-minute failure threshold and 15-minute failure-to-success sequence are **distinct detection conditions**.
- `Get-WinEvent` access depends on the local Security log and appropriate privileges; remote collection, retention, alert routing, and suppression were not validated.
- Current logic reports the first qualifying success; deduplication by Event Record ID and durable CSV/JSON output remain future engineering improvements.
- Production-quality parsing should prefer named event XML fields over positional `Properties[]` indexes where feasible, with event-ID-specific schema tests.

## ATT&CK context

**T1110 — Brute Force** is a relevant *detection hypothesis* for repeated failed authentications. **T1078 — Valid Accounts** is a relevant *investigation hypothesis* for a later successful login. **Neither technique is established as malicious activity in this authorized test.** A 4624 Type 3 event alone does not prove lateral movement, interactive control, or remote code execution.

## Analyst conclusion

**Disposition: Benign positive test / rule validation.** The event sequence and source attribution were successfully detected after resolving a schema-indexing error. The investigation shows a defensible workflow: controlled test → telemetry validation → correlation → investigate false negative → fix parser → retest. It is distinct from prior Splunk-based labs and uses only native Windows logging and PowerShell.

## Interview-ready explanation

> I built a Windows authentication correlation detector that joined 4625 failures to a later 4624 network logon using the same account, IP, and a 15-minute window. During testing, the script initially returned no alert because the 4625 Logon Type field has a different event-property index than 4624. I inspected the raw events, corrected the parser, and verified the alert against a controlled three-failure-to-success sequence. I documented the false-negative root cause and avoided classifying a lab simulation as a real intrusion.
