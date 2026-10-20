# IR-003 Study Notes — Windows Failed Logons and SMB Authentication

> **Learning companion** to [IR-003 incident report](../reports/IR-003-SMB-Authentication-Failure.md). Start with the plain-language explanation, then learn the technical vocabulary. This is an authorized lab, not a confirmed attack.

## 1. The story in 60 seconds

Kali Linux (`192.168.56.105`) tried to authenticate over the network to DC02 (`192.168.56.101`) using a wrong password for `LAB\socuser`. DC02 rejected the attempt and wrote Windows Security **Event 4625**. We found four failed-logon records between 02:42:55 and 02:47:08 on October 18, 2026. We inspected detailed fields and preserved screenshots 24–26.

**Mental model:** Kali is the visitor, DC02 is the secured building, the account is the badge name, the password is the credential, and Event 4625 is the security guard's log.

## 2. Core concepts: simple explanation + technical meaning

| Concept | Plain English | Technical detail |
|---|---|---|
| **SMB** | Windows' network file-sharing language | Server Message Block commonly uses TCP 445 and supports remote shares, authentication, and other Windows network operations |
| **Domain controller (DC)** | The domain's identity/security authority | Active Directory Domain Services authenticates domain identities and enforces directory-backed access policies |
| **Authentication** | Proving who you are | Validating credentials; separate from **authorization** (what you're allowed to access) |
| **Event 4625** | A login failed | Windows Security auditing event for an unsuccessful logon |
| **Logon Type 3** | The attempt came through the network | Network logon; not an interactive keyboard login (Type 2) or RDP remote-interactive login (Type 10) |
| **Source IP** | The computer the attempt came from | `192.168.56.105` identified Kali in the inspected event |
| **NTLM** | An older Windows sign-in approach | Challenge-response authentication family; avoid assuming an NTLM version without appropriate evidence |
| **Kerberos** | Windows' ticket-based sign-in approach | Commonly preferred for Active Directory authentication; involves ticket-granting workflows |
| **MSV1_0** | Windows authentication component | `MICROSOFT_AUTHENTICATION_PACKAGE_V1_0`, associated with NTLM-family processing; not a full packet trace |
| **SOC** | Team investigating security signals | Security Operations Center: triage, correlation, investigation, escalation, response |

## 3. Decode the event

| Field | Value in inspected evidence | What to remember |
|---|---|---|
| Event ID | `4625` | Failed logon |
| Target account | `LAB\socuser` | Who was named in the request |
| Logon Type | `3` | Network logon |
| Status | `0xC000006D` | General login failure |
| Substatus | `0xC000006A` | Bad password |
| Logon Process | `Advapi` | Windows API/logon context; **not** proof of a specific attack tool |
| Authentication Package | `MICROSOFT_AUTHENTICATION_PACKAGE_V1_0` | MSV1_0, NTLM-associated |
| Source Network Address | `192.168.56.105` | Kali lab VM |

**Common trap:** 4625 does **not** mean the user was hacked. It means an attempt failed. Four events in five minutes are worth correlating but are not sufficient to establish brute force.

## 4. Event IDs worth knowing

| Event | Why it matters |
|---|---|
| **4624** | Successful logon: did access eventually succeed? |
| **4625** | Failed logon: who, when, from where, and why? |
| **4776** | NTLM credential validation on the relevant validating system, if auditing produces it |
| **4771** | Kerberos pre-authentication failure |
| **4768** | Kerberos ticket-granting ticket request |
| **4769** | Kerberos service-ticket request |

The last four are **related telemetry to investigate**, not evidence already captured for IR-003.

## 5. Reproduce the log review safely

Run on **DC02, PowerShell** (not Kali). These commands only read Windows logs.

```powershell
# Recent failed logon timeline
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625} -MaxEvents 20 |
  Select-Object TimeCreated,Id

# Full details of latest failure
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625} -MaxEvents 1 |
  Format-List TimeCreated,Message

# Check whether successful logons were recorded recently (review context carefully)
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624} -MaxEvents 10 |
  Select-Object TimeCreated,Id
```

**Do not treat every 4624 as proof the same failed login succeeded:** compare account, source, logon type, and time.

## 6. The analyst's thinking process

1. **Verify** the event exists and read the failure reason.
2. **Identify** account, host, source IP, logon type, and exact time.
3. **Correlate** related failures and any nearby successes.
4. **Validate context**: known user error, scheduled test, outdated service credential, or unexpected activity?
5. **Assess risk**: privileged identity? unusual source? many targets? successful follow-up?
6. **Document only what the evidence proves** and note missing telemetry.

### Why this lab matters

You practiced **blue-team investigation**, not simply running Kali commands. The evidence connects an authorized test to defender-side telemetry. A hiring manager can see both hands-on operation and cautious analysis.

## 7. Defensive ideas

- Tune 4625 alerts by **account, source, host, and time window**; avoid noisy one-size-fits-all rules.
- Investigate failures involving privileged accounts with greater urgency.
- Correlate 4625 with 4624 and relevant Kerberos/NTLM events.
- Restrict unnecessary SMB access and review account privilege.
- For protocol proof, collect a properly authorized Wireshark capture rather than guessing NTLM version.

## 8. Active recall — answer before looking

1. What does Event 4625 prove?
2. What is the difference between Logon Type 3 and Type 10?
3. Which field tells you the password was incorrect?
4. Why is an IP address important in incident triage?
5. Does MSV1_0 alone prove NTLMv2?
6. Why might Domain Admin membership increase investigation priority?
7. Why shouldn't four failed attempts automatically be called brute force?
8. What extra evidence would you seek if failures were followed by a success?

<details>
<summary>Answer key</summary>

1. An unsuccessful Windows logon was recorded.
2. Type 3 is network; Type 10 is remote interactive, commonly RDP.
3. Substatus `0xC000006A`.
4. It helps attribute and correlate activity to a source, subject to NAT/proxy/context limitations.
5. No; it is associated with NTLM-family processing, not proof of version.
6. Privileged accounts can enable higher-impact access if compromised.
7. Insufficient volume/context and the activity was an authorized simulation.
8. Correlate account, source, timestamp, logon type, endpoint activity, and additional authentication telemetry.

</details>

## 9. Evidence and next lesson

- [Screenshot 24: Event details](../screenshots/24-SMB-Failed-Logon-4625-Kali-to-DC02.png)
- [Screenshot 25: Four-event timeline](../screenshots/25-Failed-Logon-Event-Timeline.png)
- [Screenshot 26: Authentication package](../screenshots/26-SMB-Authentication-Protocol-4625.png)
- **Next lab:** authorized Wireshark SMB traffic capture and protocol validation.

**Study strategy:** Review this once, explain the case aloud without reading, then answer the eight recall questions after a day or two.
