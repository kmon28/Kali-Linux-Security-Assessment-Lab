# IR-003 — SMB Authentication Failure Investigation

**Investigation date:** October 18, 2026 (local lab time)  
**Environment:** Authorized VirtualBox host-only lab, `lab.local`  
**Classification:** Controlled security simulation / blue-team investigation  
**Disposition:** Authentication failures confirmed; no successful intrusion established

## Executive summary

Four Windows Security Event ID **4625** records were observed on the Windows Server 2022 domain controller (DC02) during a controlled failed SMB authentication exercise. The attempted account was `LAB\socuser`, and the observed source address was the Kali Linux VM, `192.168.56.105`. The failures were associated with invalid password authentication. The four events occurred over approximately four minutes. This supports a small cluster of unsuccessful network logons, **not** a conclusion of brute-force activity, password spraying, or compromise.

## Scope and systems

| System | Role | Lab IP |
|---|---|---|
| Kali Linux | Authorized test source | `192.168.56.105` |
| DC02 (Windows Server 2022) | Active Directory domain controller / log source | `192.168.56.101` |
| CLIENT01 | Not used in this IR-003 exercise | `192.168.56.102` |

**Important:** IR-003 concerns authentication against **DC02**, not the earlier CLIENT01 SMB validation documented in screenshots 08–10.

## Event timeline

| Local timestamp (October 18, 2026) | Event | Observation |
|---|---|---|
| 02:42:55 AM | 4625 | Failed logon |
| 02:43:22 AM | 4625 | Failed logon |
| 02:46:54 AM | 4625 | Failed logon |
| 02:47:08 AM | 4625 | Failed logon |

The query returned seven historical 4625 events in total, including three older events from September. **Only the four October 18 events** are attributed to this test window; historical events are not automatically part of the same activity.

## Key event details

| Field | Observed value | Interpretation |
|---|---|---|
| Event ID | `4625` | Failed account logon |
| Target account | `LAB\socuser` | Account named in the failed authentication |
| Logon type | `3` | Network logon |
| Source network address | `192.168.56.105` | Kali Linux lab VM |
| Status | `0xC000006D` | General logon failure |
| Substatus | `0xC000006A` | Incorrect password |
| Logon process | `Advapi` | Windows logon API/process context |
| Authentication package | `MICROSOFT_AUTHENTICATION_PACKAGE_V1_0` | MSV1_0, associated with NTLM-family authentication |

**Protocol caveat:** The MSV1_0 field is consistent with NTLM-related processing but does not by itself establish the exact NTLM version or reconstruct the full network exchange. Packet capture or additional protocol-specific telemetry would be needed for that conclusion.

## Reproduction and collection

An authorized operator initiated controlled SMB authentication attempts from Kali toward DC02 using an incorrect password. The defender-side Windows Security log was examined in elevated PowerShell.

```powershell
# Timeline of recent failed logons
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625} -MaxEvents 20 |
    Select-Object TimeCreated,Id

# Inspect full details of the most recent failed logon
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625} -MaxEvents 1 |
    Format-List TimeCreated,Message
```

These commands read existing events; they do not modify security settings or generate additional failed logons.

## Evidence

- [Screenshot 24 — Failed SMB logon and Kali source IP](../screenshots/24-SMB-Failed-Logon-4625-Kali-to-DC02.png)
- [Screenshot 25 — Failed-logon timeline](../screenshots/25-Failed-Logon-Event-Timeline.png)
- [Screenshot 26 — Authentication package and failure details](../screenshots/26-SMB-Authentication-Protocol-4625.png)

## Analysis and triage decision

The shared account, source address, network logon type, incorrect-password substatus, and timestamps support correlation of the four failures as a short authentication-failure cluster. Because the exercise was intentionally generated in an isolated lab, the appropriate disposition is **expected simulated activity**. There is no evidence in this collection of successful authentication, account takeover, credential theft, or lateral movement.

A real SOC would check successful logons (4624), domain authentication events where applicable (such as 4776/4771), source-host ownership, asset criticality, account privilege, and whether the failures match an authorized activity or an established baseline before assigning severity.

## Defensive recommendations

1. Alert on repeated 4625 failures using **time windows, source IP, target account, and environment-specific thresholds**; investigate rather than automatically labeling every cluster brute force.
2. Correlate failed 4625 activity with successful 4624 events and relevant domain-controller authentication telemetry.
3. Review whether `socuser` requires **Domain Admins** membership. Apply least privilege only after confirming lab dependencies; do not remove permissions blindly.
4. Restrict SMB exposure to authorized management and workstation networks, and keep appropriate auditing enabled.
5. For future protocol analysis, capture authorized traffic in Wireshark and validate NTLM/Kerberos behavior instead of inferring a protocol version from one event field.

## Limitations

This report is based on screenshots and observed Windows event output, not a complete exported EVTX log or PCAP. The precise sequence of all SMB client invocations was not preserved here. Four failures alone are insufficient to establish malicious intent, brute force, password spraying, or an exploitable vulnerability.

## Skills demonstrated

Windows Security Event triage; Event ID 4625 interpretation; network-source attribution; authentication failure-code analysis; timeline correlation; evidence preservation; concise incident reporting; and evidence-based threat assessment.
