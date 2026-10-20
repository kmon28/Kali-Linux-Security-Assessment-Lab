# IR-003 | Investigating Failed SMB Authentication on a Windows Domain Controller

> **SOC case study · Windows Security Logs · Active Directory · Kali Linux**  
> **Investigation:** October 18, 2026 · **Environment:** Isolated, authorized VirtualBox lab · **Status:** Closed — expected simulated activity

[Executive brief](#1-executive-brief) · [Timeline](#3-event-timeline) · [Technical analysis](#4-technical-evidence-explained) · [Detection engineering](#6-detection-engineering) · [Evidence](#8-evidence-gallery) · [Recommendations](#9-defensive-recommendations)

---

## 1. Executive brief

### The situation — in plain English

A Kali Linux test machine attempted to sign in to a Windows domain controller using an incorrect password. Windows rejected the attempts and recorded them in its Security event log. I investigated those records to identify **who**, **where**, **when**, **how**, and **why** the authentication failed.

### The finding — technically

**Four Windows Security Event ID 4625 records** appeared on **DC02** between **02:42:55 and 02:47:08 AM** on October 18, 2026. A detailed event identified the account `LAB\socuser`, source `192.168.56.105` (Kali), **Logon Type 3**, status `0xC000006D`, substatus `0xC000006A`, and authentication package `MICROSOFT_AUTHENTICATION_PACKAGE_V1_0` (MSV1_0).

| Question | Answer |
|---|---|
| **What happened?** | A cluster of four failed network logons |
| **Where?** | DC02, the `lab.local` Active Directory domain controller |
| **Who was targeted?** | `LAB\socuser` in the inspected event |
| **Where did it originate?** | Kali Linux at `192.168.56.105` |
| **Why did it fail?** | Incorrect password (`0xC000006A`) |
| **Was access gained?** | No successful access demonstrated by this evidence |
| **Analyst disposition** | Expected, authorized lab simulation; no confirmed compromise |

**Key distinction:** A short cluster of failed logons is a **signal to investigate**, not proof of brute force or malicious intent.

### What this project demonstrates

- Generated controlled authentication telemetry and investigated it from the **defender's perspective**.
- Correlated an event timeline with account, source-IP, and Windows failure-code details.
- Interpreted Windows authentication internals without overclaiming what one event proves.
- Produced an evidence-backed SOC incident report and practical monitoring guidance.

---

## 2. Environment and scope

| Asset | Purpose | Address |
|---|---|---|
| **Kali Linux** | Authorized authentication-test source | `192.168.56.105` |
| **DC02 / Windows Server 2022** | Active Directory domain controller and Security log source | `192.168.56.101` |
| CLIENT01 / Windows 10 | Earlier, separate SMB lab; **not involved in IR-003** | `192.168.56.102` |

**Domain:** `lab.local` · **Network:** VirtualBox host-only `192.168.56.0/24`

```text
    KALI LINUX                              DC02 / WINDOWS SERVER
    192.168.56.105                          192.168.56.101
          |                                         |
          |  SMB network authentication attempt     |
          |---------------------------------------->|
          |             incorrect password          |
          |<----------------------------------------|
          |               access denied             |
          |                                         |
          |                        Windows Security Event 4625
          |                        (account, IP, time, status)
```

**Scope guardrail:** All activity was authorized within the lab. This is **not** a production breach, vulnerability exploitation, or a claim that credentials were stolen.

---

## 3. Event timeline

**Source:** DC02 Security log, Event ID `4625`.

| Time (October 18, local) | Event ID | Finding |
|---|---|---|
| 02:42:55 AM | 4625 | Failed logon recorded |
| 02:43:22 AM | 4625 | Failed logon recorded |
| 02:46:54 AM | 4625 | Failed logon recorded |
| 02:47:08 AM | 4625 | Failed logon recorded |

**Time span:** 4 minutes, 13 seconds from first to last event.

The PowerShell query returned **seven historical events overall**: four during this October 18 test window and three older events from September. Older events are **not** assumed to be related.

**Analyst note:** The timeline screenshot establishes the four event times. The detailed event screenshots establish the account, source IP, and failure information for inspected events. Without exporting and inspecting each complete record, do not assume every field is identical across all four.

---

## 4. Technical evidence explained

The table intentionally includes both a plain-English interpretation and the technical significance.

| Windows field | Observed value | Meaning / analyst use |
|---|---|---|
| **Event ID** | `4625` | Windows logged an **unsuccessful** sign-in |
| **Target account** | `LAB\socuser` | Identity used in the inspected failed attempt |
| **Logon Type** | `3` | Network authentication, rather than someone typing at the server console |
| **Source Network Address** | `192.168.56.105` | Network origin in the event; matches the Kali lab VM |
| **Status** | `0xC000006D` | General authentication failure |
| **Substatus** | `0xC000006A` | More specific reason: **incorrect password** |
| **Logon Process** | `Advapi` | Windows logon process/API context, not an attack-tool identifier |
| **Authentication Package** | `MICROSOFT_AUTHENTICATION_PACKAGE_V1_0` | MSV1_0, a Windows authentication package associated with NTLM-family processing |

### Why the failure codes matter

- **`0xC000006D`** answers: *Did the login succeed?* **No.**
- **`0xC000006A`** answers: *Why not?* **The password was incorrect.**
- **Logon Type 3** answers: *What kind of access was attempted?* **A network logon.**

This combination is more useful than merely reporting “a failed login,” because it helps distinguish a bad password from other failure reasons and narrows the investigation to network activity.

### Does MSV1_0 prove NTLMv2?

**No.** The observed authentication package is consistent with **NTLM-related Windows authentication processing**, but the log alone does not identify the exact NTLM version or provide a packet-by-packet reconstruction. Additional Windows telemetry or an authorized packet capture would be required to validate the precise exchange.

### Why the target account deserves attention

An earlier authorized LDAP group-membership check listed **`socuser` among Domain Admins**. That makes the account potentially high-impact if credentials were compromised. **No compromise was observed here**, and the membership itself does not prove a misconfiguration; it merits a **least-privilege review**.

---

## 5. Investigation workflow

| Step | Analyst action | Result |
|---|---|---|
| **1. Generate** | Initiate controlled unsuccessful SMB authentication from Kali | Expected failure |
| **2. Detect** | Inspect DC02 Windows Security events | Event ID 4625 located |
| **3. Correlate** | Compare timestamps in recent 4625 events | Four-event cluster identified |
| **4. Attribute** | Inspect source IP, account, and logon type | Kali source and network authentication identified in detailed evidence |
| **5. Explain** | Interpret status, substatus, and authentication package | Incorrect password; MSV1_0 observed |
| **6. Assess** | Compare activity against known authorized test | Closed as expected simulated activity |
| **7. Document** | Preserve screenshots and report limitations | Reproducible portfolio evidence |

### Commands used on DC02 (PowerShell)

```powershell
# Recent failed logons — fast timeline
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625} -MaxEvents 20 |
    Select-Object TimeCreated,Id

# Most recent failed logon — full event explanation
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625} -MaxEvents 1 |
    Format-List TimeCreated,Message
```

These are **read-only** commands. They retrieve existing Windows event records and do not generate login attempts.

---

## 6. Detection engineering

### Detection idea: repeated failed network logons

**Goal:** Flag clusters of Windows 4625 network-logon failures for review, especially where a privileged account or domain controller is involved.

**Suggested starting logic (illustrative, not deployed):**

```text
DATA SOURCE: Windows Security events
FILTER:
  EventID == 4625
  AND LogonType == 3

GROUP BY:
  Computer + TargetUserName + IpAddress

TIME WINDOW:
  5 minutes

EXAMPLE THRESHOLD:
  >= 4 failures in that window

OUTPUT:
  Computer, account, source IP, event count,
  first seen, last seen, status/substatus
```

**Important:** Four events in five minutes is a **demonstration threshold chosen to match this lab**, not a universally reliable production rule. Tune thresholds to the organization, account sensitivity, legitimate error rates, and logging volume. A real alert should preserve event context and support analyst triage rather than automatically classify an attacker.

### Additional correlation opportunities

| Event / source | Why an analyst would check it |
|---|---|
| **4624 — Successful logon** | Did a success follow the failures? |
| **4776 — NTLM credential validation** | Additional NTLM-related domain authentication context, if logged |
| **4771 — Kerberos pre-authentication failure** | Kerberos-specific failure context, if relevant |
| **4768 / 4769 — Kerberos ticket activity** | Whether nearby ticket activity provides useful context |
| **Windows Firewall / network telemetry** | Confirm connection direction, service exposure, and source behavior |
| **Asset and account inventory** | Determine whether source and account activity were authorized |

**No claim is made that these additional events were collected in IR-003.**

### MITRE ATT&CK context

**T1110 — Brute Force** is a *possible investigative hypothesis* when repeated authentication failures are observed. However, this case **does not establish T1110**: only four controlled failures were observed and the operator was authorized. MITRE mapping is included to demonstrate how an analyst might frame further investigation, not to label the lab as a confirmed attack.

---

## 7. SOC triage and disposition

### Questions an analyst should ask

1. Is the source IP a known workstation, scanner, test VM, or unknown host?
2. Is the targeted identity privileged or otherwise sensitive?
3. Are failures concentrated on one account, or spread across many accounts?
4. Did a successful authentication occur shortly afterward?
5. Does the activity match a maintenance window, user report, or approved security test?
6. Is the same source attempting other services or systems?

### Decision for this case

| Category | Assessment |
|---|---|
| **Activity type** | Failed network authentication |
| **Observed impact** | No successful access demonstrated |
| **Cause in lab** | Deliberate incorrect-password tests |
| **Malicious activity confirmed?** | **No** |
| **Response** | Preserve evidence, document, and close as expected simulation |
| **Escalation** | Not warranted on the observed lab evidence alone |

**What would change the decision?** Unexpected source ownership, a privileged-account success after failures, many accounts targeted, unusually high request volume, or corroborating malicious network/endpoint behavior.

---

## 8. Evidence gallery

The three screenshots are retained separately so a reviewer can verify the analysis.

| Evidence | What to look for |
|---|---|
| **[24 — Failed logon details](../screenshots/24-SMB-Failed-Logon-4625-Kali-to-DC02.png)** | Event 4625, account, failed password, and Kali source IP |
| **[25 — Event timeline](../screenshots/25-Failed-Logon-Event-Timeline.png)** | Four October 18 events and three unrelated older records |
| **[26 — Authentication detail](../screenshots/26-SMB-Authentication-Protocol-4625.png)** | Logon Process `Advapi`, MSV1_0 authentication package, status and substatus |

> **Evidence quality note:** Screenshots provide a readable audit trail, but an exported `.evtx` file and a PCAP would support more complete forensic validation. Neither is represented as collected here.

---

## 9. Defensive recommendations

| Priority | Recommendation | Rationale |
|---|---|---|
| **High** | Review whether `socuser` needs **Domain Admins** membership | Reduce potential impact if credentials are ever exposed; verify dependencies before changing permissions |
| **High** | Monitor failed logons for privileged accounts and domain controllers | Higher-value identities and systems deserve more context-aware triage |
| **Medium** | Correlate 4625 with 4624 and relevant 4776/4771 activity | Distinguish unsuccessful tests, normal mistakes, and potentially suspicious patterns |
| **Medium** | Restrict SMB to authorized hosts/networks | Reduce unnecessary network access paths |
| **Medium** | Establish baselines and tune thresholds | Prevent routine mistypes from overwhelming analysts |
| **Future validation** | Capture authorized SMB authentication traffic in Wireshark | Confirm the network protocol details that the Windows event cannot fully prove |

---

## 10. Limitations and integrity statement

- The investigation relies on observed screenshots and Windows event output; **no full EVTX export or packet capture** is included.
- The exact command sequence for each of the four failed attempts was not preserved in the report.
- Detailed event fields were inspected for selected records; not every field was individually verified for all four.
- The report does **not** demonstrate credential compromise, exploitation, password spraying, lateral movement, or a successful intrusion.
- A domain-controller event and an NTLM-associated package do not, by themselves, prove an NTLM version.
- The earlier **CLIENT01** exercise is separate and should not be conflated with this **DC02** investigation.

## 11. Interview-ready summary

> “I built an isolated Active Directory lab with Kali Linux and Windows Server, generated controlled SMB authentication failures, and investigated the defender-side Windows Security logs. I correlated four Event 4625 records within a five-minute window, traced the inspected event to Kali's IP address, and interpreted Logon Type 3, Windows failure codes, and the MSV1_0 authentication package. I then documented the evidence, proposed detection logic, and explained why the findings did not prove a brute-force attack. The exercise strengthened my Windows log analysis, authentication troubleshooting, and SOC investigation skills.”

**Skills:** Windows Event Log analysis · Active Directory · SMB authentication · incident triage · timeline correlation · detection design · MITRE ATT&CK-informed investigation · evidence-based reporting

---

*IR-003 is an educational blue-team case study conducted only on authorized lab infrastructure.*
