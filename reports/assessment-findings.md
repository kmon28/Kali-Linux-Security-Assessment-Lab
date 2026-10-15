# Kali / Active Directory Security Assessment — Evidence-Based Findings

**Environment:** Isolated VirtualBox lab | **Review date:** 2026-10-15 | **Scope:** DC02 `192.168.56.101`, CLIENT01 `192.168.56.102`, Kali `192.168.56.105`.

## Executive outcome
Reconnaissance identified reachable lab hosts and typical Active Directory service exposure. DC02 reported SMB signing as **required**, an important defensive control. LDAP queries revealed directory structure, account names, and privileged group membership; this is useful for IAM review but is not by itself a vulnerability. A controlled SMB authentication attempt against CLIENT01 failed and was corroborated by Windows Security Event 4625 with Kali's source address. A subsequent TCP/445 probe reported `filtered`, consistent with restricted SMB reachability.

## Findings matrix

| ID | Observation | Assessment | Supporting evidence |
|---|---|---|---|
| KAL-01 | Nmap `-sn 192.168.56.0/24` found four hosts up | Expected lab discovery; not a vulnerability | [02](../screenshots/02-Nmap-Host-Discovery.png) |
| KAL-02 | DC02 exposed AD-associated TCP services, including 53, 88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269, 5985 | Review attack surface and intended access; open does not mean vulnerable | [03](../screenshots/03-DC02-Service-Enumeration.png) |
| KAL-03 | `smb2-security-mode` returned `Message signing enabled and required` | **Positive control observed**; no missing-SMB-signing finding | [04](../screenshots/04-DC02-SMB-Security-Mode.png) |
| KAL-04 | LDAP rootDSE returned domain `DC=lab,DC=local` and naming contexts | Directory metadata visible; authorization context not established from screenshot alone | [05](../screenshots/05-Active-Directory-LDAP-Enumeration.png) |
| KAL-05 | Directory output included `socuser` and workstation objects | Account inventory confirmed; no claim of credential access | [06](../screenshots/06-Authenticated-AD-User-Enumeration.png) |
| KAL-06 | Domain Admins members included `Administrator` and `socuser` | **Review recommended:** verify `socuser` genuinely requires privileged group membership | [07](../screenshots/07-Privileged-Group-Enumeration.png) |
| KAL-07 | SMB client returned `NT_STATUS_LOGON_FAILURE` against CLIENT01 | Failed login; no successful access established | [08](../screenshots/08-Controlled-SMB-Authentication-Failure.png) |
| KAL-08 | Event 4625, Logon Type 3, source `192.168.56.105`, account `labattacktest` | Host telemetry corroborates failed network authentication | [09](../screenshots/09-Windows-Event-4625-Investigation.png) |
| KAL-09 | CLIENT01 `445/tcp filtered` on retest | SMB access not observed from Kali at retest; rule details not independently proven | [10](../screenshots/10-SMB-Firewall-Hardening-Retest.png) |

## Priority review: privileged group membership
The Domain Admins group contained `socuser` and `Administrator` in the lab. Because Domain Admins is highly privileged, the `socuser` membership deserves an authorization and least-privilege review. The screenshot **does not** prove this membership was unauthorized. Validate the account's intended role, whether a lower-privilege group is sufficient, and any dependency before making changes. Verify removal, if approved, with a repeat LDAP/AD query and relevant audit logs.

## Controlled authentication failure: correlation
**Kali side:** `smbclient -L //192.168.56.102 -U 'CLIENT01\\labattacktest'` produced `NT_STATUS_LOGON_FAILURE`.

**Windows side:** CLIENT01 Event 4625 at approximately 10:01:32 AM on 2026-10-15 showed Logon Type 3, account `labattacktest`, account domain `CLIENT01`, source workstation `KALI`, source IP `192.168.56.105`, source port `34074`, NTLM authentication, status `0xC000006D`, substatus `0xC000006A`.

**Interpretation:** The two observations are consistent with the same controlled failed SMB authentication test. The event indicates a failed login, not a successful intrusion or necessarily a password-spraying campaign.

**Detection idea:** Monitor Event 4625 Type 3 by source IP, account, target host, and time window; compare to successful 4624 logons and 4776/NTLM context when available. Alert thresholds should account for ordinary typing mistakes and known test windows.

## SMB filtering retest
The later command `nmap -Pn -p 445 192.168.56.102` returned `445/tcp filtered`. This supports the conclusion that the port was not accessible to the scanner at that time. A precise firewall-remediation claim would additionally require the Windows Firewall rule configuration, before/after state, and policy source.

## Next validation actions (not claimed complete)
- Export Nmap XML and command history with timestamps for repeatability.
- Capture the LDAP bind type and account authorization for directory queries.
- Review `socuser` privilege justification and least-privilege alternatives.
- Export the matching 4625 event as EVTX/XML; correlate by time and source.
- Export Windows Firewall rule state and test TCP/445 from both allowed and disallowed subnets.
- Document detection logic, false positives, and a clean retest.

**Bottom line:** This is an authorized assessment and blue-team correlation exercise, not proof of a compromised domain.
